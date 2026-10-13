#!/usr/bin/env bash
# Report rate on a GCP confidential VM: scripts/measure/report_burst.py, N requests per mode (default 200).
#   TEE=sev-snp: n2d-standard-2, AMD Milan; modes snp-ioctl and tsm.
#   TEE=tdx:     c3-standard-4; mode tsm (the TD quote).
# The VM is deleted on exit and the deletion checked (vms-deleted.txt).
#
#   TEE=sev-snp|tdx scripts/measure/gcp-report-rate.sh [ZONE]
set -euo pipefail
. "$(dirname "$0")/lib-gcloud.sh"
TEE="${TEE:-sev-snp}"
ZONE="${1:-us-central1-a}"
N="${N:-200}"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="report-rate-$TEE-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12 | tr 'A-Z' 'a-z')"
NAME="${NAME//_/-}"
OUT="$REPO/docs/measurements/evidence/${STAMP}-gcp-${TEE}-report-rate"
TMP="$(mktemp -d)"
CREATED=""
mkdir -p "$OUT"
git -C "$REPO" rev-parse --short=12 HEAD > "$OUT/code-rev.txt"
git -C "$REPO" show HEAD:scripts/measure/report_burst.py > "$TMP/report_burst.py"

cleanup() {
  set +e
  if [ -n "$CREATED" ]; then
    echo "== delete $NAME"
    for i in 1 2 3; do
      gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 && break
      gcloud compute instances describe "$NAME" --project="$PROJECT" --zone="$ZONE" >/dev/null 2>&1 || break
      sleep 10
    done
    if gcloud compute instances describe "$NAME" --project="$PROJECT" --zone="$ZONE" >/dev/null 2>&1; then
      echo "!! $NAME still exists" | tee "$OUT/vms-deleted.txt"
    else
      echo "$NAME deleted; instances left in $PROJECT: $(gcloud compute instances list --project="$PROJECT" --format='value(name)' | wc -l | tr -d ' ')" | tee "$OUT/vms-deleted.txt"
    fi
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP   # run cleanup when stopped

case "$TEE" in
  sev-snp) TYPE=n2d-standard-2; EXTRA=(--min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP); MODES="snp-ioctl tsm" ;;
  tdx)     TYPE=c3-standard-4;  EXTRA=(--confidential-compute-type=TDX); MODES="tsm" ;;
  *) echo "TEE must be sev-snp or tdx"; exit 2 ;;
esac

echo "== create $NAME ($TYPE, $TEE) in $ZONE"
CREATED=1
gcl compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" --machine-type="$TYPE" "${EXTRA[@]}" \
  --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --labels=purpose=report-rate >/dev/null
echo "$PROJECT $ZONE $NAME $TYPE $TEE" | tee "$OUT/instance.txt"
echo "== wait for ssh"
for i in $(seq 1 30); do
  gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='true' >/dev/null 2>&1 && break
  sleep 10
done
gcl compute scp "$TMP/report_burst.py" "$NAME:~/" --project="$PROJECT" --zone="$ZONE" >/dev/null

echo "== bursts of $N ($MODES)"
RUN="set +e
sudo modprobe sev-guest 2>/dev/null; sudo modprobe tdx-guest 2>/dev/null
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
uname -a > kernel.txt; ls -l /dev/sev-guest /dev/tdx_guest >> kernel.txt 2>&1; ls -ld /sys/kernel/config/tsm/report >> kernel.txt 2>&1"
for m in $MODES; do RUN="$RUN
sudo python3 report_burst.py --mode $m --n $N --out $m.json"; done
RUN="$RUN
sudo dmesg | grep -i -E 'sev|snp|tdx|tsm|quote' | tail -n 40 > dmesg.txt
true"
gcl compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command="$RUN" 2>>"$OUT/ssh.stderr" | tee "$OUT/summary.txt"
for f in $MODES kernel dmesg; do
  case "$f" in kernel|dmesg) src="$f.txt" ;; *) src="$f.json" ;; esac
  gcloud compute scp "$NAME:~/$src" "$OUT/" --project="$PROJECT" --zone="$ZONE" >/dev/null 2>>"$OUT/scp.stderr" || true
done
echo "== results in $OUT"
