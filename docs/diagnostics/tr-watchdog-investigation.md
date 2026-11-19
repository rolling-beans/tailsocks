# TailSocks tr watchdog investigation

Branch: `debug/tr-process-watchdog`

## Background

The recurring hot process was observed as `tr '\0' '\n' < /proc/$p/cmdline`.

`RootDaemon.wakeRootDaemon()` contains this exact pipeline while scanning PIDs returned by `pgrep -f -- --socket=...`: it transforms `/proc/PID/cmdline`, checks for `--statedir=`, then sends SIGUSR1. The call uses `runSu("daemon-wake", ..., timeoutMs = 8_000L)`.

`RootShell.runSu()` starts `su` using `Runtime.getRuntime().exec("su")`. On timeout it calls `process.destroy()` on that `su` Process object. This is a plausible orphan-child mechanism, but is not yet proven to be the cause of the runaway `tr`.

## Watchdog behavior

- Exact process name `tr`, root UID, exact argv byte signature `tr`, `\0`, `\n`.
- Requires `io.github.bropines.tailscaled` in the live parent chain. This intentionally fails closed and ignores reparented processes.
- Measures CPU from deltas of `utime + stime` in `/proc/PID/stat`, normalized to one logical CPU.
- Trigger: at least 20% of one CPU for 5 consecutive 1-second samples.
- A matching process older than 30 seconds is reported once but is not killed unless the CPU trigger fires.
- Captures status, raw cmdline, stat, exe, cwd, SELinux context, wchan, schedstat, io, syscall, stack, FDs, parent chain, thermal state, CPU frequencies and filtered TailSocks logcat before signaling.
- Revalidates the exact signature and starttime immediately before SIGTERM; after one second it sends SIGKILL only if the same process is still present.

Linux procfs defines `utime` as field 14, `stime` as field 15 and `starttime` as field 22. The parser removes the leading PID/comm portion through the final `)` so spaces in comm do not shift the fields.

## Safety / lifecycle

- Root execution, but no kernel, SELinux, module, boot or persistent-service changes.
- No boot persistence; the monitor stops at reboot or explicit stop.
- Does not kill unrelated `tr` processes.
- Logs: `/data/local/tmp/tailsocks-tr-watchdog/watchdog.log`; event reports are in the same directory.
- Directory mode 0700; report files mode 0600.
- Start: `/system/bin/sh /data/local/tmp/tailsocks-tr-watchdog.sh start`.
- Status: `/system/bin/sh /data/local/tmp/tailsocks-tr-watchdog.sh status`.
- Stop: `/system/bin/sh /data/local/tmp/tailsocks-tr-watchdog.sh stop`.

## First validation

1. Run `/system/bin/sh -n` on the target Android build.
2. Verify a harmless synthetic `tr '\0' '\n'` process has the expected argv byte signature.
3. Verify the ancestry predicate matches only the TailSocks root-shell chain.
4. Verify CPU percentage against a controlled process before relying on automatic termination.
5. Inspect the first event report before changing TailSocks source behavior.

## Known limitation

If `su` or its shell has already exited and `tr` has been reparented to PID 1, the strict ancestry test ignores it. This is deliberate for the first deployment. If observed, capture its PPID, command line, cgroup, SELinux context and FDs, then extend the matcher from evidence rather than killing every root-owned `tr`.