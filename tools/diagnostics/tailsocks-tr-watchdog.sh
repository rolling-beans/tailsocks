#!/system/bin/sh
# Narrow watchdog for the runaway tr created by TailSocks RootDaemon.wakeRootDaemon().
# No boot persistence; root-owned reports live under /data/local/tmp.

SCRIPT=/data/local/tmp/tailsocks-tr-watchdog.sh
DATA=/data/local/tmp/tailsocks-tr-watchdog
STATE=$DATA/state
LOG=$DATA/watchdog.log
PIDFILE=$DATA/watchdog.pid
THRESHOLD=20
STREAK_LIMIT=5
INTERVAL=1

log() { echo "$(date -Iseconds) $*" >> "$LOG"; }

is_target() {
    tp=$1
    [ -r "/proc/$tp/comm" ] || return 1
    [ "$(cat "/proc/$tp/comm" 2>/dev/null)" = tr ] || return 1
    uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/$tp/status" 2>/dev/null)
    [ "$uid" = 0 ] || return 1

    # Exact argv bytes: "tr\0\\0\0\\n\0".
    cmdhex=$(od -An -tx1 "/proc/$tp/cmdline" 2>/dev/null)
    echo "$cmdhex" | grep -Eq '74 72 00 5c 30 00 5c 6e 00' || return 1

    # Fail closed unless the TailSocks app is still in the ancestry.
    parent=$(awk '{sub(/^.*\) /,""); print $2}' "/proc/$tp/stat" 2>/dev/null)
    depth=0
    while [ -n "$parent" ] && [ "$parent" -gt 1 ] 2>/dev/null && [ "$depth" -lt 10 ]; do
        grep -aFq 'io.github.bropines.tailscaled' "/proc/$parent/cmdline" 2>/dev/null && return 0
        parent=$(awk '{sub(/^.*\) /,""); print $2}' "/proc/$parent/stat" 2>/dev/null)
        depth=$((depth + 1))
    done
    return 1
}

capture_report() {
    p=$1 start=$2 reason=$3 cpu=$4 streak=$5
    stamp=$(date +%Y%m%d-%H%M%S)
    report=$DATA/event-$stamp-p$p.log
    {
        echo "TAILSOCKS TR WATCHDOG EVENT"
        echo "time=$(date -Iseconds) pid=$p start_ticks=$start reason=$reason cpu=$cpu% streak=$streak"
        echo "threshold=$THRESHOLD% samples=$STREAK_LIMIT interval=$INTERVAL"
        echo "device=$(getprop ro.product.model) android=$(getprop ro.build.version.release)"
        echo "fingerprint=$(getprop ro.build.fingerprint)"
        uname -a
        echo "uptime=$(cat /proc/uptime)"
        echo
        echo "=== PROCESS TABLE ==="
        ps -AZ -o LABEL,PID,PPID,USER,STAT,ELAPSED,PCPU,PMEM,ARGS 2>&1 | grep -E '(^ *LABEL|tr|tailscaled|libtailscale)' | grep -v grep | head -160
        echo
        echo "=== TARGET ==="
        cat "/proc/$p/status" 2>&1
        echo "-- cmdline bytes --"; od -An -tx1c "/proc/$p/cmdline" 2>&1
        echo "-- stat --"; cat "/proc/$p/stat" 2>&1
        echo "-- exe/cwd/SELinux --"
        readlink "/proc/$p/exe" 2>&1
        readlink "/proc/$p/cwd" 2>&1
        cat "/proc/$p/attr/current" 2>&1
        echo "-- wchan/schedstat/io/syscall/stack --"
        cat "/proc/$p/wchan" "/proc/$p/schedstat" "/proc/$p/io" "/proc/$p/syscall" "/proc/$p/stack" 2>&1
        echo "-- fds --"; ls -l "/proc/$p/fd" 2>&1
        for f in /proc/$p/fdinfo/*; do
            [ -r "$f" ] || continue
            echo "--- $f ---"; cat "$f" 2>&1
        done
        echo
        echo "=== PARENT CHAIN ==="
        q=$p depth=0
        while [ -n "$q" ] && [ "$q" -gt 1 ] 2>/dev/null && [ "$depth" -lt 10 ]; do
            echo "--- PID $q ---"
            cat "/proc/$q/status" 2>&1 | grep -E '^(Name|Pid|PPid|State|Uid|Gid):'
            readlink "/proc/$q/exe" 2>&1
            od -An -tx1c "/proc/$q/cmdline" 2>&1 | head -12
            q=$(awk '{sub(/^.*\) /,""); print $2}' "/proc/$q/stat" 2>/dev/null)
            [ -n "$q" ] || break
            depth=$((depth + 1))
        done
        echo
        echo "=== CPU / THERMAL ==="
        cat /proc/loadavg
        head -20 /proc/stat
        dumpsys thermalservice 2>&1 | head -100
        dumpsys battery 2>&1 | grep -E 'status:|health:|level:|temperature:|voltage:' | head -30
        for z in /sys/class/thermal/thermal_zone*; do
            [ -d "$z" ] || continue
            echo "$z type=$(cat "$z/type" 2>/dev/null) temp=$(cat "$z/temp" 2>/dev/null)"
        done
        for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
            [ -r "$f" ] && echo "$f=$(cat "$f" 2>/dev/null)"
        done
        echo
        echo "=== TAILSOCKS LOGCAT ==="
        logcat -b all -d -v threadtime -t 8000 2>/dev/null | grep -iE 'RootUtils|TailscaledService|daemon-wake|root shell timed out|network moved|network reaches the internet|tailscaled' | tail -200
    } > "$report" 2>&1
    chmod 600 "$report"
    log "EVENT pid=$p start=$start reason=$reason cpu=$cpu% streak=$streak report=$report"
}

monitor_loop() {
    [ "$(id -u)" = 0 ] || { echo "ERROR: monitor must run as root" >&2; exit 2; }
    mkdir -p "$STATE"; chmod 700 "$DATA" "$STATE"
    HZ=$(getconf CLK_TCK 2>/dev/null)
    case "$HZ" in ''|*[!0-9]*|0) HZ=100 ;; esac
    log "START pid=$$ HZ=$HZ threshold=$THRESHOLD% streak=$STREAK_LIMIT interval=$INTERVAL"
    loops=0

    while :; do
        now_cs=$(awk '{printf "%.0f\n",$1*100}' /proc/uptime 2>/dev/null)
        [ -n "$now_cs" ] || now_cs=0

        for p in $(pgrep -x tr 2>/dev/null); do
            is_target "$p" || { rm -f "$STATE/$p" "$STATE/$p.reported"; continue; }

            values=$(awk '{sub(/^.*\) /,""); print $2,$12+$13,$20}' "/proc/$p/stat" 2>/dev/null)
            [ -n "$values" ] || continue
            set -- $values
            ppid=$1 ticks=$2 start=$3
            sf=$STATE/$p
            old_start= old_ticks=0 old_cs=$now_cs streak=0
            if [ -r "$sf" ]; then read old_start old_ticks old_cs streak < "$sf"; fi

            cpu=0
            if [ "$old_start" = "$start" ] && [ "$now_cs" -gt "$old_cs" ] 2>/dev/null; then
                dticks=$((ticks-old_ticks)); dcs=$((now_cs-old_cs))
                [ "$dticks" -ge 0 ] || dticks=0
                cpu=$((dticks*10000/(HZ*dcs)))
                if [ "$cpu" -ge "$THRESHOLD" ]; then
                    streak=$((streak+1))
                    log "sample pid=$p ppid=$ppid cpu=$cpu% streak=$streak"
                else
                    streak=0
                fi
            fi
            age_cs=$((now_cs-start*100/HZ))
            printf '%s %s %s %s\n' "$start" "$ticks" "$now_cs" "$streak" > "$sf"

            if [ "$age_cs" -ge 3000 ] && [ ! -e "$sf.reported" ]; then
                capture_report "$p" "$start" "runtime-over-30s-observation-only" "$cpu" "$streak"
                : > "$sf.reported"
            fi

            if [ "$streak" -ge "$STREAK_LIMIT" ]; then
                capture_report "$p" "$start" "sustained-cpu" "$cpu" "$streak"
                # Revalidate signature and starttime before signaling to avoid PID reuse.
                if is_target "$p"; then
                    current_start=$(awk '{sub(/^.*\) /,""); print $20}' "/proc/$p/stat" 2>/dev/null)
                    if [ "$current_start" = "$start" ]; then
                        kill -TERM "$p" 2>/dev/null && log "SIGTERM pid=$p"
                        sleep 1
                        if is_target "$p"; then
                            current_start=$(awk '{sub(/^.*\) /,""); print $20}' "/proc/$p/stat" 2>/dev/null)
                            if [ "$current_start" = "$start" ]; then
                                kill -KILL "$p" 2>/dev/null && log "SIGKILL pid=$p"
                            fi
                        fi
                    else
                        log "PID $p starttime changed; skipped signal"
                    fi
                else
                    log "PID $p no longer matches TailSocks signature; skipped signal"
                fi
                rm -f "$sf" "$sf.reported"
            fi
        done

        for sf in "$STATE"/*; do
            [ -e "$sf" ] || continue
            case "$sf" in *.reported) continue ;; esac
            p=$(basename "$sf")
            if [ ! -r "/proc/$p/comm" ] || [ "$(cat "/proc/$p/comm" 2>/dev/null)" != tr ]; then
                rm -f "$sf" "$sf.reported"
            fi
        done
        loops=$((loops+1))
        [ $((loops%60)) -ne 0 ] || log "heartbeat pid=$$ uptime=$(cat /proc/uptime)"
        sleep "$INTERVAL"
    done
}

start_monitor() {
    [ "$(id -u)" = 0 ] || { echo "ERROR: run as root" >&2; exit 2; }
    mkdir -p "$STATE"; chmod 700 "$DATA" "$STATE"
    if [ -r "$PIDFILE" ]; then
        read oldpid < "$PIDFILE"
        if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null &&
           grep -aFq "$SCRIPT" "/proc/$oldpid/cmdline" 2>/dev/null; then
            echo "RUNNING pid=$oldpid"; exit 0
        fi
    fi
    nohup /system/bin/sh "$SCRIPT" monitor >> "$LOG" 2>&1 </dev/null &
    newpid=$!; echo "$newpid" > "$PIDFILE"; chmod 600 "$PIDFILE"
    sleep 1
    if kill -0 "$newpid" 2>/dev/null; then
        echo "STARTED pid=$newpid"; tail -8 "$LOG"
    else
        echo "FAILED"; tail -80 "$LOG"; exit 1
    fi
}

stop_monitor() {
    [ -r "$PIDFILE" ] || { echo "NOT RUNNING"; exit 0; }
    read p < "$PIDFILE"
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null &&
       grep -aFq "$SCRIPT" "/proc/$p/cmdline" 2>/dev/null; then
        kill -TERM "$p" 2>/dev/null || true
        sleep 1
        if kill -0 "$p" 2>/dev/null && grep -aFq "$SCRIPT" "/proc/$p/cmdline" 2>/dev/null; then
            kill -KILL "$p" 2>/dev/null || true
        fi
        echo "STOP SIGNAL SENT pid=$p"
    else
        echo "NOT RUNNING (stale pidfile)"
    fi
    rm -f "$PIDFILE"
}

status_monitor() {
    if [ -r "$PIDFILE" ]; then
        read p < "$PIDFILE"
        if [ -n "$p" ] && kill -0 "$p" 2>/dev/null &&
           grep -aFq "$SCRIPT" "/proc/$p/cmdline" 2>/dev/null; then
            echo "RUNNING pid=$p"
        else
            echo "STOPPED (stale pidfile)"
        fi
    else
        echo STOPPED
    fi
    echo "LOG=$LOG"
    echo "REPORTS=$DATA/event-*.log"
    ps -A -o PID,PPID,STAT,ELAPSED,PCPU,ARGS 2>/dev/null | grep -E 'tr-watchdog|[[:space:]]tr([[:space:]]|$)' | grep -v grep
}

case "$1" in
    start) start_monitor ;;
    stop) stop_monitor ;;
    status) status_monitor ;;
    tail) tail -n 100 "$LOG" 2>/dev/null ;;
    monitor) monitor_loop ;;
    *) echo "Usage: $SCRIPT {start|stop|status|tail|monitor}"; exit 2 ;;
esac
