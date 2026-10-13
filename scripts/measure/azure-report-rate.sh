#!/usr/bin/env bash
# Report rate on an Azure confidential VM (AMD SEV-SNP under the paravisor, DCasv5): scripts/measure/report_burst.py in modes
# vtpm-quote and azure-hcl, N requests each (default 200), with a tpm2_getrandom baseline. Also tries snp-ioctl and
# tsm, which a paravisor guest is not expected to offer; their failure is recorded. Everything is created in one
# throwaway resource group, which is deleted on exit; its absence is checked (vm-deleted.txt). SSH is admitted from
# this address only.
#
#   scripts/measure/azure-report-rate.sh [LOCATION]
set -euo pipefail
LOC="${1:-westeurope}"
SIZE="${SIZE:-Standard_DC2as_v5}"
IMAGE="${IMAGE:-Canonical:ubuntu-24_04-lts:cvm:latest}"
N="${N:-200}"
NFRESH="${NFRESH:-100}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RG="report-rate-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
VM="rr-snp"
OUT="$REPO/docs/measurements/evidence/${STAMP}-azure-sev-snp-report-rate"
TMP="$(mktemp -d)"
CREATED=""
mkdir -p "$OUT"
git -C "$REPO" rev-parse --short=12 HEAD > "$OUT/code-rev.txt"
git -C "$REPO" show HEAD:scripts/measure/report_burst.py > "$TMP/report_burst.py"

cleanup() {
  set +e
  if [ -n "$CREATED" ]; then
    echo "== delete resource group $RG"
    az group delete -n "$RG" --yes >/dev/null 2>>"$OUT/az.stderr"
    echo "resource group $RG exists after delete: $(az group exists -n "$RG")" | tee "$OUT/vm-deleted.txt"
    echo "resource groups named report-rate-* left: $(az group list --query "length([?starts_with(name,'report-rate-')])" -o tsv)" | tee -a "$OUT/vm-deleted.txt"
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP   # run cleanup when stopped

ssh-keygen -q -t ed25519 -N '' -f "$TMP/key"
MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
echo "== resource group $RG in $LOC"
CREATED=1
az group create -n "$RG" -l "$LOC" --tags purpose=report-rate >/dev/null
echo "== create $VM ($SIZE, ConfidentialVM, $IMAGE)"
az vm create -g "$RG" -n "$VM" --size "$SIZE" --image "$IMAGE" \
  --security-type ConfidentialVM --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-secure-boot true --enable-vtpm true \
  --admin-username azureuser --ssh-key-values "$TMP/key.pub" \
  --public-ip-sku Standard --nsg-rule NONE --output json > "$TMP/vm.json" 2>>"$OUT/az.stderr"
IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["publicIpAddress"])' "$TMP/vm.json")"
NSG="$(az network nsg list -g "$RG" --query '[0].name' -o tsv)"
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n ssh-from-here --priority 1000 --access Allow --protocol Tcp \
  --direction Inbound --source-address-prefixes "$MYIP/32" --destination-port-ranges 22 >/dev/null
echo "$LOC $RG $VM $SIZE $IMAGE" | tee "$OUT/instance.txt"
az vm show -g "$RG" -n "$VM" --query '{size:hardwareProfile.vmSize,security:securityProfile,zone:zones}' -o json > "$OUT/instance-security.json"
SSHO=(-i "$TMP/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$TMP/known_hosts" -o ConnectTimeout=10)
SSH=(ssh "${SSHO[@]}" "azureuser@$IP")

echo "== wait for ssh"
for i in $(seq 1 40); do "${SSH[@]}" true >/dev/null 2>&1 && break; sleep 10; done
scp "${SSHO[@]}" "$TMP/report_burst.py" "azureuser@$IP:~/" >/dev/null 2>>"$OUT/ssh.stderr"

echo "== bursts of $N"
"${SSH[@]}" "set +e
sudo DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null && sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y tpm2-tools >/dev/null
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
uname -a > kernel.txt; ls -l /dev/sev-guest /dev/tpmrm0 >> kernel.txt 2>&1; ls -ld /sys/kernel/config/tsm/report >> kernel.txt 2>&1
tpm2_getcap handles-persistent >> kernel.txt 2>&1
sudo python3 report_burst.py --mode vtpm-quote --n $N --baseline 20 --out vtpm-quote.json
sudo python3 report_burst.py --mode azure-hcl --n $N --baseline 20 --out azure-hcl.json
sudo python3 report_burst.py --mode azure-hcl-fresh --n $NFRESH --out azure-hcl-fresh.json
sudo python3 report_burst.py --mode snp-ioctl --n 5 --out snp-ioctl.json
sudo python3 report_burst.py --mode tsm --n 5 --out tsm.json
sudo dmesg | grep -i -E 'sev|snp|tpm|hv_|vmbus|paravisor' | tail -n 60 > dmesg.txt
true" 2>>"$OUT/ssh.stderr" | tee "$OUT/summary.txt"
scp "${SSHO[@]}" "azureuser@$IP:~/vtpm-quote.json" "azureuser@$IP:~/azure-hcl.json" "azureuser@$IP:~/azure-hcl-fresh.json" "azureuser@$IP:~/snp-ioctl.json" \
  "azureuser@$IP:~/tsm.json" "azureuser@$IP:~/kernel.txt" "azureuser@$IP:~/dmesg.txt" "$OUT/" >/dev/null 2>>"$OUT/ssh.stderr" || true
echo "== results in $OUT"
