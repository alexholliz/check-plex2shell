#!/usr/bin/env bash
#
# check-plex2shell.sh — read-only compromise check for Plex Media Server
#
# Based on the checker by gmolveau:
# https://gist.github.com/gmolveau/b02c2e58b877cf138e2859dbfb5cc20e
#
# Checks whether a Plex install shows signs of compromise via the
# "Plex2Shell" exploit chain (CVE-2026-96652 / -96654 / -96655 / -96656)
# and the malware dropped in the wild (XMRig miner, "myawesomeproxy").
#
# Vulnerable:     Plex Media Server < 1.43.3.10861 (including 1.43.3.10828)
# Patched in:     1.43.3.10861
#
# The script is strictly read-only. It needs some root access to read
# native install logs — it will tell you if it skipped a check.
#
# Usage:
#   bash check-plex2shell.sh
#
# Exit codes:
#   0 = no compromise indicators found
#   1 = action needed (vulnerable version and/or compromise indicators)
#   2 = Plex Media Server not detected
#
set -u

FIX_MIN=1.43.3.10861   # first fixed build
SELF=check-plex2shell.sh

# ---------------------------------------------------------------- output
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
  C_G=''; C_Y=''; C_R=''; C_B=''; C_0=''
fi

FAILS=0
WARNS=0
SKIPS=0
PASS ()  { printf '%s[PASS]%s  %s\n' "$C_G" "$C_0" "$*"; }
WARN ()  { printf '%s[WARN]%s  %s\n' "$C_Y" "$C_0" "$*"; WARNS=$((WARNS+1)); }
FAIL ()  { printf '%s[FAIL]%s  %s\n' "$C_R" "$C_0" "$*"; FAILS=$((FAILS+1)); }
SKIP ()  { printf '%s[SKIP]%s  %s\n' "$C_B" "$C_0" "$*"; SKIPS=$((SKIPS+1)); }

echo "Plex Media Server compromise check (Plex2Shell, CVE-2026-96652/54/55/56)"
echo "Read-only. Nothing is modified. ${C_Y}Run with sudo for the deepest checks.${C_0}"
echo

# ---------------------------------------------------------------- utils
# version >= threshold ?   Handles "1.43.4.10903-e5521bd8c" and 3-field versions.
ver_ge () {
  local a="${1#v}" b="${2#v}"
  a="${a%%-*}"
  b="${b%%-*}"
  [[ "$a" =~ ^[0-9]+(\.[0-9]+){2,3}$ ]] || return 2
  [[ "$b" =~ ^[0-9]+(\.[0-9]+){2,3}$ ]] || return 2
  local -a A B
  IFS=. read -r -a A <<< "$a"
  IFS=. read -r -a B <<< "$b"
  local i x y
  for i in 0 1 2 3; do
    x=$((10#${A[i]:-0})); y=$((10#${B[i]:-0}))
    if [ "$x" -gt "$y" ]; then return 0; fi
    if [ "$x" -lt "$y" ]; then return 1; fi
  done
  return 0
}


RUN_ROOT () {  # try privileged, fall back to unprivileged
  sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null
}

# ------------------------------------------------------- 1) find the install
INSTALLS=()           # strings: "docker <container>" or "native"
DOCKER=()
NATIVE=0

if command -v docker >/dev/null 2>&1; then
  while IFS=$'\t' read -r name image; do
    P=$(docker top "$name" aux 2>/dev/null \
        || docker top "$name" -eo user,pid,comm,args 2>/dev/null \
        || docker top "$name" 2>/dev/null)
    if printf '%s\n' "$P" | grep -aq '[P]lex Media Server'; then
      DOCKER+=("$name")
    fi
  done < <(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null)
fi

# native install = package installed or systemd unit present
# (do NOT use pgrep: host sees processes running inside containers)
if dpkg -s plexmediaserver >/dev/null 2>&1 \
   || rpm -q plexmediaserver >/dev/null 2>&1 \
   || [ -f /lib/systemd/system/plexmediaserver.service ] \
   || [ -f /etc/systemd/system/plexmediaserver.service ]; then
  NATIVE=1
fi

for c in "${DOCKER[@]}";  do INSTALLS+=("docker $c"); done
[ "$NATIVE" -eq 1 ] && INSTALLS+=("native")

if [ ${#INSTALLS[@]} -eq 0 ]; then
  echo "${C_R}Plex Media Server not found (no plex container, service, or /var/lib/plexmediaserver).${C_0}"
  echo "If Plex runs elsewhere, run this script on that machine."
  exit 2
fi

printf 'Detected install(s): %s\n\n' "${INSTALLS[*]}"

VULNERABLE=0
VERSION_UNKNOWN=0

for inst in "${INSTALLS[@]}"; do
  kind=${inst%% *}
  what=${inst#* }

  echo "${C_B}--- Checking: $inst ---${C_0}"

  # ------------------------------------------------------- 2) version
  VER=""
  if [ "$kind" = docker ]; then
    c=$what
    IDENTITY=$(docker exec "$c" sh -c '
      if command -v curl >/dev/null 2>&1; then
        exec curl -fsS --max-time 5 http://127.0.0.1:32400/identity
      elif command -v wget >/dev/null 2>&1; then
        exec wget -qO- -T 5 http://127.0.0.1:32400/identity
      else
        exit 127
      fi' 2>/dev/null)
    VER=$(printf '%s\n' "$IDENTITY" | sed -n 's/.* version="\([^"]*\)".*/\1/p' | tail -n1)
  else
    VER=$(dpkg -s plexmediaserver 2>/dev/null | sed -n 's/^Version: *//p' | head -n1)
    [ -z "$VER" ] && VER=$(rpm -q plexmediaserver 2>/dev/null | sed 's/^plexmediaserver-//')
    if [ -z "$VER" ] && command -v curl >/dev/null 2>&1; then
      VER=$(curl -sfm 5 http://127.0.0.1:32400/identity | sed -n 's/.* version="\([^"]*\)".*/\1/p' | tail -n1)
    fi
  fi

  if [ -n "$VER" ]; then
    ver_ge "$VER" "$FIX_MIN"
    case $? in
      0)
        PASS "Plex version $VER is patched (>= $FIX_MIN)"
        ;;
      1)
        FAIL "Plex version $VER is VULNERABLE (< $FIX_MIN) — the Plex2Shell chain is exploited in the wild. Upgrade now."
        VULNERABLE=1
        ;;
      *)
        WARN "Invalid Plex version value: $VER"
        VERSION_UNKNOWN=1
        ;;
    esac
  else
    WARN "Could not determine Plex version. Check manually: Plex Web > Settings > General, or http://<server>:32400/identity"
    VERSION_UNKNOWN=1
  fi

  if [ "$kind" = docker ]; then
    c=$what

    # ------------------------------------------------- 3) container processes
    P=$(docker top "$c" aux 2>/dev/null || docker top "$c" -eo user,pid,comm 2>/dev/null)
    if [ -n "$P" ]; then
      if printf '%s\n' "$P" | grep -aviE 'grep|plex-check' \
         | grep -aiE 'xmrig|myawesomeproxy|cryptonight|stratum\+tcp|minerd|kdevtmpfsi|kinsing|/tmp/[a-z0-9]{6,}$' ; then
        FAIL "Suspicious process found in container $c (see line above)"
      else
        PASS "No miner/proxy processes in container $c"
      fi
    else
      SKIP "Cannot list container processes (docker top failed)"
    fi

    # ------------------------------------------------- 4) files in container
    F=$(docker exec "$c" sh -c '
        command -v find >/dev/null 2>&1 || { echo __NOFIND__; exit 0; }
        find /tmp /var/tmp -maxdepth 2 \( -iname "*xmrig*" -o -iname "*miner*" -o -iname "*proxy*" -o -name "*.sh" -o -name "*.so" \) 2>/dev/null
        for base in "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server" "/config/Library/Application Support/Plex Media Server"; do
          [ -d "$base" ] && find "$base/Codecs" -type f \( -name "*.so" -o -name "*.sh" \) 2>/dev/null
        done' 2>/dev/null)
    if [ -z "$F" ]; then
      SKIP "Cannot inspect container filesystem (find not available inside container)"
    elif printf '%s\n' "$F" | grep -aq __NOFIND__; then
      SKIP "Cannot inspect container filesystem (find not available inside container)"
    else
      SUS=$(printf '%s\n' "$F" | grep -aiE 'xmrig|myawesomeproxy|miner|/tmp/.*\.(sh|so)$')
      SO=$(printf '%s\n' "$F" | grep -ai '/Codecs/' | grep -aivE '/lib[a-z0-9_]*_(encoder|decoder)\.(so|sh)$')
      if [ -n "$SUS" ]; then
        FAIL "Suspicious files in container $c:"
        printf '       %s\n' "$SUS"
      else
        PASS "No suspicious files in /tmp, /var/tmp of container $c"
      fi
      if [ -n "$SO" ]; then
        WARN "Files exist in the Codecs folder of container $c — review them (a known attack drops a malicious .so there):"
        printf '       %s\n' "$SO"
      else
        PASS "Codecs folder empty (no dropped libraries)"
      fi
    fi

    # ------------------------------------------------- 5) container network
    N=""
    NETWORK_CHECKED=0
    if docker exec "$c" sh -c 'command -v ss >/dev/null 2>&1'; then
      if N=$(docker exec "$c" sh -c 'ss -tunp state established' 2>/dev/null); then
        NETWORK_CHECKED=1
      fi
    elif command -v nsenter >/dev/null 2>&1 && command -v ss >/dev/null 2>&1; then
      CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' "$c" 2>/dev/null)
      if [[ "$CONTAINER_PID" =~ ^[1-9][0-9]*$ ]] \
         && N=$(nsenter -t "$CONTAINER_PID" -n ss -tunp state established 2>/dev/null); then
        NETWORK_CHECKED=1
      fi
    fi

    if [ "$NETWORK_CHECKED" -eq 1 ]; then
      if printf '%s\n' "$N" | grep -aE ':(3333|14444|14433|45700)([[:space:]]|$)'; then
        FAIL "Container has established connections on a known mining port (line above)"
      else
        PASS "No connections to known mining ports from container $c"
      fi
    else
      SKIP "Cannot check container network state (need ss in the container, or nsenter and ss on the host)"
    fi

    # ------------------------------------------------- 6) Plex access logs
    L=$(docker logs "$c" --since 72h 2>&1 | grep -aiE 'transcode/universal\?[^ ]*url=(https?|ftp|gopher)|GET /player/timeline\?\$|\$X-Plex-Token|myawesomeproxy' | head -n 8)
    if [ -n "$L" ]; then
      FAIL "Exploit signatures found in container logs of $c:"
      printf '       %s\n' "$L"
    else
      PASS "No exploit signatures in container logs (last 72h)"
    fi
  fi
done

# ---------------------------------------------------------------- native
if [ "$NATIVE" -eq 1 ]; then
  echo "${C_B}--- Checking: native install ---${C_0}"
  DATA="/var/lib/plexmediaserver/Library/Application Support/Plex Media Server"

  P=$(ps aux 2>/dev/null)
  if printf '%s\n' "$P" | grep -aviE 'grep|plex-check' \
     | grep -aiE 'xmrig|myawesomeproxy|cryptonight|stratum\+tcp|minerd|kdevtmpfsi|kinsing' \
     | grep -av 'Plex Plug-in'; then
    FAIL "Suspicious process found on host (see line above)"
  else
    PASS "No miner/proxy processes on host"
  fi

  T=$(RUN_ROOT find /tmp /var/tmp -maxdepth 2 \( -iname "*xmrig*" -o -iname "*miner*" -o -iname "*proxy*" -o -name "*.so" \) 2>/dev/null)
  if [ -n "$T" ]; then
    FAIL "Suspicious files in /tmp or /var/tmp:"
    printf '       %s\n' "$T"
  else
    PASS "No suspicious files in /tmp or /var/tmp"
  fi

  N=$(ss -tunp state established 2>/dev/null | grep -aE ':(3333|14444|14433|45700)\b' )
  E=$(ss -tunp state established 2>/dev/null | grep -a 'users:(("\"/tmp' )
  if [ -n "$N$E" ]; then
    FAIL "Suspicious established connection(s) on host:"
    printf '       %s\n' "$N$E"
  else
    PASS "No connections to known mining ports, none running from /tmp"
  fi

  LOG="$DATA/Logs/Plex Media Server.log"
  if RUN_ROOT test -f "$LOG"; then
    L=$(RUN_ROOT grep -aiE 'transcode/universal\?[^ ]*url=(https?|ftp|gopher)|GET /player/timeline\?\$|\$X-Plex-Token|myawesomeproxy' "$LOG" 2>/dev/null | tail -n 8)
    if [ -n "$L" ]; then
      FAIL "Exploit signatures found in native Plex logs:"
      printf '       %s\n' "$L"
    else
      PASS "No exploit signatures in native Plex logs"
    fi
  else
    SKIP "Cannot read native Plex logs without root — for a deeper check run: sudo bash $SELF"
  fi

  # ------------------------------------------------- simple persistence check
  K=$(RUN_ROOT find /root/.ssh /home/*/.ssh -name authorized_keys -newermt '30 days ago' 2>/dev/null)
  if [ -n "$K" ]; then
    WARN "authorized_keys modified in the last 30 days (check it is you):"
    printf '       %s\n' "$K"
  else
    PASS "No recently modified authorized_keys"
  fi
  CR=$(RUN_ROOT grep -rlE 'curl|wget|/tmp/' /etc/cron.d /var/spool/cron/crontabs 2>/dev/null)
  if [ -n "$CR" ]; then
    WARN "Cron entries reference curl/wget//tmp (check it is you):"
    printf '       %s\n' "$CR"
  else
    PASS "No suspicious cron entries"
  fi
fi

# ---------------------------------------------------------------- summary
echo
echo "${C_B}============================== summary ==============================${C_0}"
if [ "$VULNERABLE" -eq 1 ]; then
  echo "${C_R}RESULT: FAIL — Plex is VULNERABLE to Plex2Shell. Upgrade immediately.${C_0}"
elif [ "$FAILS" -gt 0 ]; then
  echo "${C_R}RESULT: FAIL — $FAILS compromise indicator(s) found. Investigate. Do NOT:${C_0}"
  echo "       delete evidence; isolate the machine first (unplug from network)."
elif [ "$VERSION_UNKNOWN" -eq 1 ]; then
  echo "${C_Y}RESULT: UNKNOWN — could not confirm your Plex version. Check manually.${C_0}"
elif [ "$SKIPS" -gt 0 ]; then
  echo "${C_Y}RESULT: INCOMPLETE — no indicators found, but $SKIPS check(s) were skipped.${C_0}"
elif [ "$WARNS" -gt 0 ]; then
  echo "${C_Y}RESULT: PASS with $WARNS item(s) to review manually (see WARN lines above).${C_0}"
else
  echo "${C_G}RESULT: PASS — patched version, no compromise indicators found.${C_0}"
fi
echo
echo "Remediation if anything is wrong:"
echo "  1. Upgrade Plex to >= $FIX_MIN (prefer the latest available release)"
echo "  2. Disable Plex 'Remote Access' if you do not need it"
echo "  3. Rotate your plex.tv password and revoke/refresh the server token"
echo "  4. If any [FAIL] IOC above fired: isolate the machine and reinstall"
echo "     from scratch (docker: recreate container + delete its data dir)"

stay=0
if [ "$VULNERABLE" -eq 1 ] || [ "$VERSION_UNKNOWN" -eq 1 ] || [ "$FAILS" -gt 0 ] || [ "$SKIPS" -gt 0 ]; then
  stay=1
fi
exit "$stay"
