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
## Runtime observation and deployment (2026-11-19)

One live runaway instance was previously observed as PID 31849, PPID 31806, root UID, SELinux context `u:r:ksu:s0`, argv `tr '\0' '\n'`. At capture it had existed for about 2 h 6 min 51 s, with about 91.6 min accumulated CPU time and a sampled average near 72.2% of one logical CPU. Its ancestry included the TailSocks app process `io.github.bropines.tailscaled`.

Watchdog deployed to the OnePlus 13 at `/data/local/tmp/tailsocks-tr-watchdog.sh`, root-owned mode 0700. Runtime data directory: `/data/local/tmp/tailsocks-tr-watchdog/`, mode 0700. Monitor started at 2026-11-19 15:40:01 +03:00, PID 12761; `CLK_TCK=100`. The active script SHA-256 on device is `4028cfa00a223800ec56c328005533c178cda3ab67ba2ea509431404248e8ae6`.

Validation performed: Android `/system/bin/sh -n` passed; synthetic `tr '\0' '\n'` argv-byte signature matched; `/proc/PID/stat` parser returned expected PPID/ticks/starttime fields; Toybox `ps` output uses `%CPU` and `%MEM`; watchdog status confirmed RUNNING. Initial measured monitor CPU was about 0.2–0.3% over short sampling windows. No TailSocks target was running during the first deployment checks, so actual anomaly-trigger/termination remains to be validated on a real recurrence.

Commands on device:

```sh
/system/bin/sh /data/local/tmp/tailsocks-tr-watchdog.sh status
/system/bin/sh /data/local/tmp/tailsocks-tr-watchdog.sh tail
/system/bin/sh /data/local/tmp/tailsocks-tr-watchdog.sh stop
```

Event reports are written before the target receives SIGTERM. A target that remains after one second receives SIGKILL only after the PID, exact argv signature, TailSocks ancestry, and starttime are checked again.
Additional live safety check: a synthetic, idle `tr '\0' '\n'` process launched from an unrelated SSH shell survived while the watchdog was active; no anomaly was logged. This validates the fail-closed ancestry filter against that unrelated process shape, but does not yet exercise the CPU-triggered kill path.
## Android notifications

Event notifications are posted locally through `/system/bin/cmd notification post`, executed as Android shell UID 2000 via `su 2000 -c`. Running the command as root UID 0 was tested and rejected by this ROM's notification path; the shell UID route was verified to create an active `com.android.shell` notification.

- Notification channel: `shell_cmd` (Shell command), Android default importance.
- A matching `tr` older than 30 seconds produces an observation notification stating that no process was terminated.
- A sustained-CPU event produces a notification after the signal attempt, including the actual action result and report path.
- Notifications use a big-text style and a unique tag per PID/starttime, so separate events remain distinguishable.
- Notification success/failure is recorded in `watchdog.log` as `NOTIFICATION_POSTED` or `NOTIFICATION_FAILED`.
- No Termux:API dependency, external app permission, network connection, or persistent Android setting is required.

Validated on-device with a test notification posted as UID 2000. The shell notification record was active with default channel importance. If the user has disabled the Shell app's notifications or the `Shell command` channel, Android may suppress visual alerts; Do Not Disturb can also affect presentation.