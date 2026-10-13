#!/usr/bin/env bash
# Report rate on an AWS EC2 AMD SEV-SNP guest: scripts/measure/report_burst.py in modes snp-ioctl and tsm, N requests each
# (default 200), the same test as drill D8 on GCP. A throwaway key pair and a security group admitting SSH from this
# address only are deleted with the instance; the deletion is checked and written to vm-deleted.txt.
#
#   scripts/measure/aws-report-rate.sh [REGION] [AZ]
set -euo pipefail
REGION="${1:-us-east-2}"
AZ="${2:-us-east-2a}"
TYPE="${TYPE:-c6a.large}"
N="${N:-200}"
AMI_PARAM="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="report-rate-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
OUT="$REPO/docs/measurements/evidence/${STAMP}-aws-sev-snp-report-rate"
TMP="$(mktemp -d)"
ID="" SG="" KEY="$NAME"
export AWS_PAGER=""
mkdir -p "$OUT"
git -C "$REPO" rev-parse --short=12 HEAD > "$OUT/code-rev.txt"
git -C "$REPO" show HEAD:scripts/measure/report_burst.py > "$TMP/report_burst.py"   # the committed probe, not the working copy

cleanup() {
  set +e
  if [ -n "$ID" ]; then
    echo "== terminate $ID"
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"
    echo "instance $ID: $(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
      --query 'Reservations[0].Instances[0].State.Name' --output text)" | tee "$OUT/vm-deleted.txt"
    ID=""
  fi
  if [ -n "$SG" ]; then
    aws ec2 delete-security-group --region "$REGION" --group-id "$SG" && echo "security group $SG deleted" | tee -a "$OUT/vm-deleted.txt"
    SG=""
  fi
  if aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY" >/dev/null 2>&1; then
    aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY" && echo "key pair $KEY deleted" | tee -a "$OUT/vm-deleted.txt"
  fi
  echo "instances tagged report-rate-* not terminated: $(aws ec2 describe-instances --region "$REGION" \
    --filters 'Name=tag:Name,Values=report-rate-*' 'Name=instance-state-name,Values=pending,running,stopping,stopped' \
    --query 'length(Reservations[].Instances[])' --output text)" | tee -a "$OUT/vm-deleted.txt"
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP   # run cleanup when stopped

echo "== key pair and security group (SSH from this address only)"
aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" --key-type ed25519 --query KeyMaterial --output text > "$TMP/key"
chmod 600 "$TMP/key"
VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "report rate $STAMP" --vpc-id "$VPC" --query GroupId --output text)"
MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null

echo "== launch $TYPE in $AZ with AmdSevSnp=enabled"
AMI="$(aws ssm get-parameter --region "$REGION" --name "$AMI_PARAM" --query Parameter.Value --output text)"
SUB="$(aws ec2 describe-subnets --region "$REGION" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
  --cpu-options AmdSevSnp=enabled --key-name "$KEY" --security-group-ids "$SG" \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=purpose,Value=report-rate}]" \
  --query 'Instances[0].InstanceId' --output text)"
echo "$REGION $AZ $ID $AMI $TYPE" | tee "$OUT/instance.txt"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
  --query 'Reservations[0].Instances[0].{type:InstanceType,az:Placement.AvailabilityZone,cpu:CpuOptions}' --output json > "$OUT/instance-cpu.json"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSHO=(-i "$TMP/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$TMP/known_hosts" -o ConnectTimeout=10)
SSH=(ssh "${SSHO[@]}" "ubuntu@$IP")

echo "== wait for ssh"
for i in $(seq 1 40); do "${SSH[@]}" true >/dev/null 2>&1 && break; sleep 10; done
scp "${SSHO[@]}" "$TMP/report_burst.py" "ubuntu@$IP:~/" >/dev/null 2>>"$OUT/ssh.stderr"

echo "== bursts of $N"
"${SSH[@]}" "set +e
sudo modprobe sev-guest 2>/dev/null
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
uname -a > kernel.txt; ls -l /dev/sev-guest >> kernel.txt 2>&1; ls -ld /sys/kernel/config/tsm/report >> kernel.txt 2>&1
sudo python3 report_burst.py --mode snp-ioctl --n $N --out snp-ioctl.json
sudo python3 report_burst.py --mode tsm --n $N --out tsm.json
sudo dmesg | grep -i -E 'sev|snp|tsm' | tail -n 40 > dmesg-sev.txt
true" 2>>"$OUT/ssh.stderr" | tee "$OUT/summary.txt"
scp "${SSHO[@]}" "ubuntu@$IP:~/snp-ioctl.json" "ubuntu@$IP:~/tsm.json" "ubuntu@$IP:~/kernel.txt" "ubuntu@$IP:~/dmesg-sev.txt" "$OUT/" >/dev/null 2>>"$OUT/ssh.stderr" || true
echo "== results in $OUT"
