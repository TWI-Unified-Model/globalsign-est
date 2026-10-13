# Sourced by the hardware scripts. The Compute API has timed out under us twice (29 September during a copy;
# 1 October before a second VM's run, when the trap deleted both VMs before their output was copied back).
#
# gcl: run gcloud, and run it again (up to four times, 15 s apart) only when gcloud itself failed to reach the
# Compute API — a crash, a read timeout, a 5xx — never when the remote command failed: that status is returned
# as it is. Such a failure happens before an ssh session starts, so a retried `compute ssh` runs its command
# once.
gcl() {
  local i rc err
  for i in 1 2 3 4; do
    err="$(mktemp)"
    rc=0
    gcloud "$@" 2> >(tee "$err" >&2) || rc=$?   # not `if gcloud …; fi; rc=$?`: that gives 0 for a failure (05.10)
    if [ "$rc" -eq 0 ]; then
      rm -f "$err"
      return 0
    fi
    sleep 1   # let tee finish writing
    if grep -q -E "gcloud crashed|Read timed out|ReadTimeout|ConnectionResetError|Connection aborted|HTTPError 5[0-9][0-9]|Error 5[0-9][0-9]|backendError|internalError" "$err"; then
      rm -f "$err"
      echo "!! gcloud could not reach the Compute API (try $i of 4); again in 15 s" >&2
      sleep 15
      continue
    fi
    rm -f "$err"
    return $rc
  done
  return $rc
}

# snapshot DIR PATH...: the committed tree of HEAD at DIR (git archive): what the guest runs is the commit recorded,
# never files that change while the run goes on.
snapshot() {
  local dir="$1"; shift
  mkdir -p "$dir"
  git -C "$REPO" archive HEAD "$@" | tar -x -C "$dir"
}
