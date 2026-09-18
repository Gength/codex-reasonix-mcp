import { access, constants, mkdtemp, open, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

import { runCommand, type CommandOptions, type CommandResult } from './command.js';
import { BridgeError } from './errors.js';

/**
 * SandboxedCommandRunner — the single authority that wraps bridge subprocesses
 * which execute repository-controlled content (verification commands, the
 * external secret scanner, Git hooks) in an OS-level sandbox.
 *
 * Posture (fail closed):
 * - network disabled;
 * - filesystem read-only outside the worktree, with credential paths hidden;
 * - worktree writable; /tmp private and writable;
 * - minimal sanitized environment (inherited from src/command.ts);
 * - if no sandbox engine is available, execution is refused unless the
 *   explicit `allowUnsandboxed` escape hatch is set.
 */
export type SandboxEngine = 'bubblewrap' | 'seatbelt';
export type BubblewrapNetworkIsolation = 'namespace' | 'seccomp';

export interface SandboxStatus {
  available: boolean;
  engine: SandboxEngine | null;
  networkIsolation?: BubblewrapNetworkIsolation;
  reason?: string;
}

export interface SandboxedCommandOptions {
  /** Writable inside the sandbox; commands run with this as the writable root. */
  worktree: string;
  /**
   * Read-only bind for the source repository (needed by git-ops profiles so
   * git can read objects/refs/hooks when the repo is hidden by an overlay).
   */
  repositoryRoot?: string;
  /** Additional read-only binds (e.g. the commit transaction dir for hooks). */
  readOnlyPaths?: readonly string[];
  /**
   * Canonical writable scratch path for seatbelt profiles (symlink-resolved
   * host temp). Falls back to `os.tmpdir()` when omitted.
   */
  tmpDir?: string;
  /**
   * Per-command scratch directory (seatbelt): the profile allows writes only
   * here and under the worktree, and TMPDIR/TMP/TEMP are pinned to it.
   */
  scratchDir?: string;
  argv: CommandOptions['argv'];
  cwd: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  env?: Readonly<Record<string, string>>;
  signal?: AbortSignal;
}

export interface CredentialOverlay {
  path: string;
  kind: 'dir' | 'file';
}

/**
 * Paths whose contents are hidden from sandboxed commands: per-user
 * credential stores and configuration that routinely holds tokens.
 */
const CREDENTIAL_HOME_ENTRIES: ReadonlyArray<readonly [string, 'dir' | 'file']> = [
  ['.ssh', 'dir'],
  ['.gnupg', 'dir'],
  ['.aws', 'dir'],
  ['.config', 'dir'],
  ['.codex', 'dir'],
  ['.kube', 'dir'],
  ['.docker', 'dir'],
  ['.password-store', 'dir'],
  ['.netrc', 'file'],
  ['.npmrc', 'file'],
  ['.yarnrc', 'file'],
  ['.gitconfig', 'file'],
  ['.git-credentials', 'file'],
  // macOS keychain stores live under ~/Library/Keychains.
  [path.join('Library', 'Keychains'), 'dir'],
];

export async function resolveCredentialOverlays(
  homeDir: string = os.homedir(),
): Promise<CredentialOverlay[]> {
  const overlays: CredentialOverlay[] = [];
  const candidates: Array<readonly [string, 'dir' | 'file']> = [
    ...CREDENTIAL_HOME_ENTRIES.map(([name, kind]) => [path.join(homeDir, name), kind] as const),
    ['/root', 'dir'],
  ];
  for (const [candidate, kind] of candidates) {
    try {
      const info = await stat(candidate);
      if ((kind === 'dir' && info.isDirectory()) || (kind === 'file' && info.isFile())) {
        overlays.push({ path: candidate, kind });
      }
    } catch {
      // Missing path — nothing to hide.
    }
  }
  return overlays;
}

const BPF_LD_W_ABS = 0x20;
const BPF_JMP_JEQ_K = 0x15;
const BPF_RET_K = 0x06;
const SECCOMP_DATA_ARCH_OFFSET = 4;
const SECCOMP_DATA_NR_OFFSET = 0;
const AUDIT_ARCH_X86_64 = 0xc000003e;
const X32_SYSCALL_BIT = 0x40000000;
const SECCOMP_RET_KILL_PROCESS = 0x80000000;
const SECCOMP_RET_ERRNO = 0x00050000;
const SECCOMP_RET_ALLOW = 0x7fff0000;
const EPERM = 1;

// socket(2) plus every operation needed to use a socket. io_uring is blocked
// too: newer kernels can create/connect sockets through io_uring opcodes.
const NETWORK_SYSCALLS = [
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307, 425, 426, 427,
] as const;

type BpfInstruction = readonly [code: number, jt: number, jf: number, k: number];

/**
 * Build a deny-network filter for the x86_64 Linux ABI. A network namespace is
 * preferred; this is only for hosts that prohibit CLONE_NEWNET entirely.
 */
export function buildNetworkSeccompFilter(): Buffer {
  if (process.arch !== 'x64') {
    throw new Error(`seccomp network fallback is unsupported on ${process.arch}`);
  }
  const instructions: BpfInstruction[] = [
    [BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET],
    [BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64],
    [BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS],
    [BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET],
  ];
  for (const syscall of NETWORK_SYSCALLS) {
    instructions.push(
      [BPF_JMP_JEQ_K, 0, 1, syscall],
      [BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM],
      [BPF_JMP_JEQ_K, 0, 1, syscall | X32_SYSCALL_BIT],
      [BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM],
    );
  }
  instructions.push([BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW]);

  const filter = Buffer.alloc(instructions.length * 8);
  for (const [index, [code, jt, jf, k]] of instructions.entries()) {
    const offset = index * 8;
    filter.writeUInt16LE(code, offset);
    filter.writeUInt8(jt, offset + 2);
    filter.writeUInt8(jf, offset + 3);
    filter.writeUInt32LE(k >>> 0, offset + 4);
  }
  return filter;
}

/** Pure bwrap argv builder; `overlays` hide credential paths. */
export function buildBwrapArgv(
  options: SandboxedCommandOptions,
  overlays: readonly CredentialOverlay[],
  networkIsolation: BubblewrapNetworkIsolation = 'namespace',
): [string, ...string[]] {
  const argv: string[] = [
    'bwrap',
    '--die-with-parent',
    // --unshare-pid makes bwrap fork a pidns-resident inner process: the
    // outer launcher exits and the spawned child.pid no longer identifies
    // the sandboxed command. The inner process keeps the launcher's process
    // group (it must NOT --new-session, or it would escape group kills), so
    // runCommand's kill(-child.pid) still reaches it, and the pid namespace
    // guarantees descendants die with the command.
    '--unshare-user',
    '--unshare-ipc',
    '--unshare-uts',
    '--unshare-pid',
    '--ro-bind',
    '/',
    '/',
  ];
  if (networkIsolation === 'namespace') argv.push('--unshare-net');
  else argv.push('--seccomp', '3');
  for (const overlay of overlays) {
    if (overlay.kind === 'dir') {
      argv.push('--tmpfs', overlay.path);
    } else {
      argv.push('--ro-bind', '/dev/null', overlay.path);
    }
  }
  argv.push('--tmpfs', '/tmp', '--proc', '/proc', '--dev', '/dev');
  if (options.repositoryRoot) {
    argv.push('--ro-bind', options.repositoryRoot, options.repositoryRoot);
  }
  for (const readOnlyPath of options.readOnlyPaths ?? []) {
    argv.push('--ro-bind', readOnlyPath, readOnlyPath);
  }
  argv.push(
    '--bind',
    options.worktree,
    options.worktree,
    '--chdir',
    options.cwd,
    '--',
    ...options.argv,
  );
  return argv as [string, ...string[]];
}

function escapeProfilePath(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/** Pure Seatbelt profile builder (macOS). */
export function buildSeatbeltProfile(
  options: SandboxedCommandOptions,
  overlays: readonly CredentialOverlay[],
): string {
  const lines = ['(version 1)', '(allow default)', '(deny network*)'];
  for (const overlay of overlays) {
    lines.push(`(deny file-read* (subpath "${escapeProfilePath(overlay.path)}"))`);
  }
  lines.push(`(deny file-write* (subpath "/"))`);
  // git and other tools open /dev/null for writing; the write deny above
  // must not break them.
  lines.push('(allow file-write* (literal "/dev/null"))');
  // Hardlink exfiltration: a hardlink to a hidden credential file created
  // inside the writable worktree resolves to the worktree path, bypassing
  // path-based read denies. Deny link creation outright.
  lines.push('(deny file-link)');
  lines.push(`(allow file-write* (subpath "${escapeProfilePath(options.worktree)}"))`);
  // Guaranteed writable scratch space: the per-command scratch directory
  // (seatbelt, TMPDIR-pinned) or, when omitted, the canonical host temp.
  // The rest of the filesystem stays read-only or denied.
  lines.push(
    `(allow file-write* (subpath "${escapeProfilePath(options.scratchDir ?? options.tmpDir ?? os.tmpdir())}"))`,
  );
  if (options.repositoryRoot) {
    lines.push(`(allow file-read* (subpath "${escapeProfilePath(options.repositoryRoot)}"))`);
  }
  for (const readOnlyPath of options.readOnlyPaths ?? []) {
    lines.push(`(allow file-read* (subpath "${escapeProfilePath(readOnlyPath)}"))`);
  }
  return lines.join('\n');
}

let cachedSandbox: SandboxStatus | undefined;

async function probeBwrapSeccomp(): Promise<boolean> {
  if (process.arch !== 'x64') return false;
  const root = await mkdtemp(path.join(os.tmpdir(), 'codex-reasonix-seccomp-'));
  const filterPath = path.join(root, 'network-filter.bpf');
  let filterFile: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await writeFile(filterPath, buildNetworkSeccompFilter(), { mode: 0o600 });
    filterFile = await open(filterPath, 'r');
    const probe = await runCommand({
      argv: [
        'bwrap',
        '--die-with-parent',
        '--unshare-user',
        '--unshare-ipc',
        '--unshare-uts',
        '--unshare-pid',
        '--ro-bind',
        '/',
        '/',
        '--tmpfs',
        '/tmp',
        '--proc',
        '/proc',
        '--dev',
        '/dev',
        '--seccomp',
        '3',
        '--',
        '/bin/true',
      ],
      cwd: root,
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
      passFds: [filterFile.fd],
    });
    return probe.exitCode === 0;
  } catch {
    return false;
  } finally {
    await filterFile?.close().catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }
}

/**
 * Detect and probe the platform sandbox engine. Results are cached for the
 * process lifetime; use {@link resetSandboxCache} in tests.
 */
export async function detectSandbox(): Promise<SandboxStatus> {
  if (cachedSandbox) return cachedSandbox;
  let status: SandboxStatus;
  if (process.platform === 'linux') {
    const probe = await runCommand({
      argv: [
        'bwrap',
        '--ro-bind',
        '/',
        '/',
        '--unshare-user',
        '--unshare-ipc',
        '--unshare-net',
        '--unshare-uts',
        '--unshare-pid',
        '--',
        '/bin/true',
      ],
      cwd: os.tmpdir(),
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
    });
    if (probe.exitCode === 0) {
      status = { available: true, engine: 'bubblewrap', networkIsolation: 'namespace' };
    } else if (await probeBwrapSeccomp()) {
      // ponytail: deny-list fallback for hosts with CLONE_NEWNET disabled;
      // use a real network namespace when the host permits it.
      status = { available: true, engine: 'bubblewrap', networkIsolation: 'seccomp' };
    } else {
      status = {
        available: false,
        engine: 'bubblewrap',
        reason: `bwrap probe failed: ${probe.stderr.trim().slice(0, 512) || 'non-zero exit'}`,
      };
    }
  } else if (process.platform === 'darwin') {
    try {
      await access('/usr/bin/sandbox-exec', constants.X_OK);
      status = { available: true, engine: 'seatbelt' };
    } catch {
      status = {
        available: false,
        engine: 'seatbelt',
        reason: '/usr/bin/sandbox-exec not found',
      };
    }
  } else {
    status = {
      available: false,
      engine: null,
      reason: `no sandbox engine for platform ${process.platform}`,
    };
  }
  cachedSandbox = status;
  return status;
}

export function resetSandboxCache(): void {
  cachedSandbox = undefined;
}

/**
 * Run a repository-content command inside the OS sandbox. The explicit
 * `allowUnsandboxed` escape hatch bypasses sandbox detection and execution;
 * otherwise the function fails closed when no engine is available.
 */
export async function runSandboxed(
  options: SandboxedCommandOptions,
  allowUnsandboxed: boolean,
  detect: () => Promise<SandboxStatus> | SandboxStatus = detectSandbox,
): Promise<CommandResult> {
  if (allowUnsandboxed) {
    return await runCommand({
      argv: options.argv,
      cwd: options.cwd,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: options.maxOutputBytes,
      env: options.env,
      signal: options.signal,
    });
  }
  const status = await detect();
  if (!status.available) {
    throw new BridgeError(
      'sandbox_unavailable',
      `Command sandbox is unavailable (${status.reason ?? status.engine ?? 'no engine'}); ` +
        'refusing to execute repository content unsandboxed',
    );
  }
  // Resolve symlinks (e.g. /tmp -> /private/tmp, /var -> /private/var on
  // macOS) so host-side paths match the paths visible inside the sandbox
  // mounts and the canonical paths the kernel checks against seatbelt
  // subpath filters.
  const [worktree, cwd, tmpDir] = await Promise.all([
    realpath(options.worktree),
    realpath(options.cwd),
    realpath(os.tmpdir()),
  ]);
  const repositoryRoot = options.repositoryRoot
    ? await realpath(options.repositoryRoot)
    : undefined;
  const readOnlyPaths = options.readOnlyPaths
    ? await Promise.all(options.readOnlyPaths.map((p) => realpath(p)))
    : undefined;
  const overlays = await resolveCredentialOverlays();
  // Pin temp so tools honoring TMPDIR always have a writable scratch space:
  // bubblewrap exposes a private tmpfs at /tmp; seatbelt cannot mount one, so
  // the command gets a dedicated scratch directory and the profile allows
  // writes only to that directory (the rest of the host temp stays denied).
  const sandboxEnv: Record<string, string> = { ...(options.env ?? {}) };
  let scratchDir: string | undefined;
  if (status.engine === 'bubblewrap') {
    sandboxEnv.TMPDIR = '/tmp';
    sandboxEnv.TMP = '/tmp';
    sandboxEnv.TEMP = '/tmp';
  } else {
    scratchDir = await mkdtemp(path.join(tmpDir, 'codex-reasonix-scratch-'));
    sandboxEnv.TMPDIR = scratchDir;
    sandboxEnv.TMP = scratchDir;
    sandboxEnv.TEMP = scratchDir;
  }
  const sandboxOptions: SandboxedCommandOptions = {
    ...options,
    worktree,
    cwd,
    repositoryRoot,
    readOnlyPaths,
    tmpDir,
    scratchDir,
  };
  let filterRoot: string | undefined;
  let filterFile: Awaited<ReturnType<typeof open>> | undefined;
  try {
    if (status.engine === 'bubblewrap' && status.networkIsolation === 'seccomp') {
      filterRoot = await mkdtemp(path.join(tmpDir, 'codex-reasonix-seccomp-'));
      await writeFile(path.join(filterRoot, 'network-filter.bpf'), buildNetworkSeccompFilter(), {
        mode: 0o600,
      });
      filterFile = await open(path.join(filterRoot, 'network-filter.bpf'), 'r');
    }
    const argv: [string, ...string[]] =
      status.engine === 'bubblewrap'
        ? buildBwrapArgv(sandboxOptions, overlays, status.networkIsolation)
        : [
            '/usr/bin/sandbox-exec',
            '-p',
            buildSeatbeltProfile(sandboxOptions, overlays),
            '--',
            ...options.argv,
          ];
    return await runCommand({
      argv,
      cwd,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: options.maxOutputBytes,
      env: sandboxEnv,
      signal: options.signal,
      passFds: filterFile ? [filterFile.fd] : undefined,
    });
  } finally {
    if (filterFile) await filterFile.close().catch(() => undefined);
    if (filterRoot) await rm(filterRoot, { recursive: true, force: true });
    if (scratchDir) {
      await rm(scratchDir, { recursive: true, force: true });
    }
  }
}
