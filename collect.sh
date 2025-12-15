#!/bin/bash
set -eu

OUT="${1:-/var/tmp/ai_host_facts.json}"

os_release="$(cat /etc/os-release 2>/dev/null || true)"
kernel="$(uname -a)"
uptime_s="$(cut -d. -f1 /proc/uptime 2>/dev/null || echo "")"

# ---------------- NETWORK ----------------

listeners="$(ss -tulpen 2>/dev/null | head -n 200 || true)"
outbound_conns="$(ss -tunp state established 2>/dev/null | head -n 200 || true)"
outbound_shells="$(ss -tunp state established 2>/dev/null \
  | egrep -i 'bash|sh|python|perl|ruby|nc|socat|php' \
  | head -n 200 || true)"



# ---------------- PROCESSES ----------------

processes="$(ps -eo user:20,pid,ppid,etimes,comm,args --no-headers 2>/dev/null \
  | awk '$1=="root" || $4>3600 {print}' \
  | head -n 250 || true)"

# ---------------- PERSISTENCE ----------------

etc_cron="$(
  (
    cat /etc/crontab 2>/dev/null
    find /etc/cron.* -type f -maxdepth 1 -print -exec sed -n '1,200p' {} \; 2>/dev/null
  ) | head -n 400 || true
)"

user_cron="$(
  for u in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$u" 2>/dev/null | sed "s/^/user=$u /" | head -n 100
  done | head -n 400 || true
)"

# ---- Cron execution targets (high-signal) ----

cron_exec_targets="$(
  crontab -l 2>/dev/null | awk '
    $0 !~ /^#/ && NF >= 6 {
      cmd=""; for (i=6;i<=NF;i++) cmd=cmd $i " "; print cmd
    }' \
  | sed 's/[;&|].*//' \
  | tr -s ' ' '\n' \
  | grep '^/' \
  | sort -u \
  | head -n 20
)"

cron_exec_details=""
for target in $cron_exec_targets; do
  if [ -f "$target" ]; then
    trust="normal"
    case "$target" in
      /mnt/*|/tmp/*|/dev/shm/*) trust="cross_boundary" ;;
    esac

    cron_exec_details="$cron_exec_details
TARGET: $target
TRUST: $trust
META:
$(ls -l "$target" 2>/dev/null)
SHA256:
$(sha256sum "$target" 2>/dev/null | awk '{print $1}')
HEAD:
$(sed -n '1,50p' "$target" 2>/dev/null)
----"
  fi
done

# rc.local + init.d
rc_local_meta="$(if [ -f /etc/rc.local ]; then ls -l /etc/rc.local; sha256sum /etc/rc.local 2>/dev/null; fi)"
initd_list="$(ls -1 /etc/init.d 2>/dev/null | head -n 200 || true)"

# ---------------- PRIVILEGE ----------------

uid0_users="$(awk -F: '$3==0 {print $1":"$6":"$7}' /etc/passwd 2>/dev/null || true)"

sudoers_hashes="$(
  (
    sha256sum /etc/sudoers 2>/dev/null
    find /etc/sudoers.d -type f -maxdepth 1 -exec sha256sum {} \; 2>/dev/null
  ) | head -n 200 || true
)"

# ---------------- AUTHENTICATION (IR-CRITICAL) ----------------

last_logins="$(last -n 20 2>/dev/null || true)"

failed_logins="$(
  grep -i 'failed password' /var/log/auth.log 2>/dev/null | tail -n 20 || true
)"

sudo_usage="$(
  grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -n 20 || true
)"

ssh_config_risky="$(
  grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysCommand|AllowUsers|AllowGroups)' \
    /etc/ssh/sshd_config 2>/dev/null || true
)"

wtmp_meta="$(ls -l /var/log/wtmp 2>/dev/null || true)"

# ---------------- ARTIFACTS ----------------

weird_bins="$(
  (
    ls -la /tmp /dev/shm 2>/dev/null
    find /tmp /dev/shm -maxdepth 2 -type f -perm -111 -ls 2>/dev/null
  ) | head -n 200 || true
)"

# ---------------- PACKAGES ----------------

pkg_mode="none"
pkg_sample=""
pkg_top=""
pkg_count=""

if command -v dpkg-query >/dev/null 2>&1; then
  pkg_mode="dpkg"
  pkg_count="$(dpkg-query -W 2>/dev/null | wc -l | tr -d ' ')"
  pkg_sample="$(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | head -n 300)"
  pkg_top="$(dpkg-query -W -f='${Package}\n' 2>/dev/null \
    | egrep -i 'ssh|sshd|nginx|apache|docker|containerd|bind|cron|rsyslog|auditd' \
    | head -n 200 || true)"
fi

# ---------------- EMIT JSON ----------------

jq -n \
  --arg os_release "$os_release" \
  --arg kernel "$kernel" \
  --arg uptime_s "$uptime_s" \
  --arg listeners "$listeners" \
  --arg processes "$processes" \
  --arg outbound_conns "$outbound_conns" \
  --arg outbound_shells "$outbound_shells" \
  --arg etc_cron "$etc_cron" \
  --arg user_cron "$user_cron" \
  --arg cron_exec_details "$cron_exec_details" \
  --arg rc_local_meta "$rc_local_meta" \
  --arg initd_list "$initd_list" \
  --arg uid0_users "$uid0_users" \
  --arg sudoers_hashes "$sudoers_hashes" \
  --arg last_logins "$last_logins" \
  --arg failed_logins "$failed_logins" \
  --arg sudo_usage "$sudo_usage" \
  --arg ssh_config_risky "$ssh_config_risky" \
  --arg wtmp_meta "$wtmp_meta" \
  --arg weird_bins "$weird_bins" \
  --arg pkg_mode "$pkg_mode" \
  --arg pkg_count "$pkg_count" \
  --arg pkg_sample "$pkg_sample" \
  --arg pkg_top "$pkg_top" \
'{
  collected_at: (now | todate),
  os_release: $os_release,
  kernel: $kernel,
  uptime_seconds: $uptime_s,
  packages: {
    mode: $pkg_mode,
    count: $pkg_count,
    sample: $pkg_sample,
    serviceish: $pkg_top
  },
  processes: $processes,
#  listeners: $listeners,
  network_activity: {
    listeners: $listeners,
    established_connections: $outbound_conns,
    shell_like_outbound: $outbound_shells
  },
  persistence: {
    etc_cron: $etc_cron,
    user_cron: $user_cron,
    cron_exec_details: $cron_exec_details,
    rc_local_meta: $rc_local_meta,
    initd_list: $initd_list
  },
  privilege: {
    uid0_users: $uid0_users,
    sudoers_hashes: $sudoers_hashes
  },
  authentication: {
    last_logins: $last_logins,
    failed_logins: $failed_logins,
    sudo_usage: $sudo_usage,
    ssh_config_risky: $ssh_config_risky,
    wtmp_meta: $wtmp_meta
  },
  suspicious_artifacts: {
    tmp_execs: $weird_bins
  }
}' > "$OUT"

echo "Wrote $OUT"
