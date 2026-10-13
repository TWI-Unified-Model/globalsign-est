# How long a confidential VM takes to produce fresh Evidence

Each run asks a fresh VM for N fresh attestation reports in a row, one at a time (N = 200), and times each request.
This is the cost a protocol pays when every session or re-attestation binds its own value (a nonce or a binder) into
a new hardware report. Designs that attest a key once and sign per-session values with it do not pay it.

## Results (October 5, 2026, plus the September GCP runs)

| platform | path | per request | requests over 1 s | sustained | run |
|---|---|---|---|---|---|
| AWS SEV-SNP, c6a.large, us-east-2a | `/dev/sev-guest`, SNP_GET_EXT_REPORT | median 6.99 ms, max 7.84 ms | 0 of 200 | 143/s | `evidence/20261005T142729Z-aws-sev-snp-report-rate` |
| same VM | configfs-tsm | median 7.87 ms, max 8.83 ms | 0 of 200 | 133/s | same |
| GCP SEV-SNP, n2d-standard-2, us-central1-c | SNP_GET_EXT_REPORT | median 7.67 ms | 19 of 200, every tenth, 10.23–10.24 s | 1.0/s | `evidence/20261005T144514Z-gcp-sev-snp-report-rate` |
| same VM | configfs-tsm | median 7.96 ms | 20 of 200, every tenth, 10.23 s | 0.97/s | same |
| GCP SEV-SNP, five runs of September 26 and 30 | SNP_GET_EXT_REPORT | median 7.6–8.2 ms | 20 of 200 each, every tenth, 10.22–10.26 s | 0.97/s | drill D8 of the runs `20260926T183015Z`, `20260926T185214Z`, `20260926T202045Z`, `20260926T234444Z`, `20260930T171748Z` in github.com/nikolaichuk7/tacra-est (`evidence/`) |
| GCP TDX, c3-standard-4, us-central1-a | configfs-tsm (TD quote) | median 38.8 ms, max 43.4 ms | 0 of 200 | 25/s | `evidence/20261005T145025Z-gcp-tdx-report-rate` |
| Azure SEV-SNP (paravisor), Standard_DC2as_v5, westeurope | vTPM quote with a 32-byte nonce (persistent AK 0x81000003) | median 45.7 ms, of which about 8 ms is starting tpm2-tools | 0 of 200 | 20/s | `evidence/20261005T143829Z-azure-sev-snp-report-rate` |
| same VM | write 64 bytes to NV 0x01400002, read the HCL report at 0x01400001 until it carries them | median 2,017 ms (100 of 100; about 67 reads each) | n/a | about 0.5/s | same, `azure-hcl-fresh.json` |
| same VM | `/dev/sev-guest`, configfs-tsm | not available to the guest (no device; no tsm provider) | | | same |

`evidence/20261005T142942Z-azure-sev-snp-report-rate` is an earlier run on the same VM type without per-call detail,
with the same picture: the vTPM quote took 45.4 ms. Read right after the write, only 55 of 200 HCL reports carried the
new data.

## The same runs from this repository (October 13, 2026)

The three scripts were run again from this repository on 13 October 2026, as a check that they work from here and
that the figures hold; each run created its VM, measured, copied its results into `evidence/` and deleted the VM.

| platform | path | per request | requests over 1 s | sustained | run |
|---|---|---|---|---|---|
| AWS SEV-SNP, c6a.large, us-east-2a | SNP_GET_EXT_REPORT | median 7.0 ms, max 8.6 ms | 0 of 200 | 143/s | `evidence/20261013T144517Z-aws-sev-snp-report-rate` |
| same VM | configfs-tsm | median 7.97 ms, max 9.09 ms | 0 of 200 | 125/s | same |
| GCP SEV-SNP, n2d-standard-2, us-central1-c | SNP_GET_EXT_REPORT | median 7.96 ms | 19 of 200, every tenth, 10.23–10.25 s | 1.021/s | `evidence/20261013T143538Z-gcp-sev-snp-report-rate` |
| same VM | configfs-tsm | median 8.0 ms | 20 of 200, every tenth, 10.23–10.23 s | 0.97/s | same |
| GCP TDX, c3-standard-4, us-central1-a | configfs-tsm (TD quote) | median 41.77 ms, max 58.96 ms | 0 of 200 | 24/s | `evidence/20261013T144712Z-gcp-tdx-report-rate` |
| Azure SEV-SNP (paravisor), Standard_DC2as_v5, westeurope | vTPM quote with a 32-byte nonce (persistent AK 0x81000003) | median 44.06 ms, max 59.37 ms | 0 of 200 | 23/s | `evidence/20261013T144930Z-azure-sev-snp-report-rate` |
| same VM | write 64 bytes to NV 0x01400002, read the HCL report at 0x01400001 until it carries them | median 2,701 ms (100 of 100; 2,017 ms on 5 October) | n/a | about 0.4/s | same, `azure-hcl-fresh.json` |
| same VM | `/dev/sev-guest`, configfs-tsm | not available to the guest, as on 5 October | | | same |

## Why the GCP SEV-SNP stalls are 10 s
Every stall is five sleeps of the Linux guest driver's 2 s retry. Linux v7.0:
- `arch/x86/include/asm/sev.h`, lines 159–160: `SNP_REQ_MAX_RETRY_DURATION (60*HZ)` and `SNP_REQ_RETRY_DELAY (2*HZ)`;
- `arch/x86/coco/sev/core.c`, lines 1831–1841: "The host may return SNP_GUEST_VMM_ERR_BUSY if the request has been
  throttled. Retry in the driver…".

The guest log shows nothing during a stall. We see the timing, not the host's reason.

## Limits
- **One run each** for AWS, Azure and GCP TDX: one instance type, one region. Other types, regions or bare metal may
  differ. Azure TDX was not measured.
- **Only the request in the guest is timed:** no network and no appraisal.
- **Azure:** a per-request value reaches the hardware report through the paravisor's HCL report, at about one report
  every 2 to 3 s (2.0 s on 5 October, 2.7 s on 13 October). The fast per-request path is the vTPM quote.

## Reproduce
You need your own cloud account. Each script creates one VM, runs `scripts/measure/report_burst.py` in it, copies the
results to `evidence/`, deletes the VM and records the deletion. Each run keeps one small VM for a few minutes, up to about 15 on Azure.

    scripts/measure/aws-report-rate.sh us-east-2 us-east-2a        # AWS SEV-SNP (AmdSevSnp=enabled)
    scripts/measure/azure-report-rate.sh westeurope                 # Azure DCasv5 confidential VM
    TEE=sev-snp scripts/measure/gcp-report-rate.sh us-central1-c    # GCP SEV-SNP
    TEE=tdx scripts/measure/gcp-report-rate.sh us-central1-a        # GCP TDX
    python3 scripts/measure/burst_stats.py docs/measurements/evidence/<run>/<mode>.json

**Provenance.** The runs were made from the development branch of github.com/nikolaichuk7/tacra-est; `code-rev.txt` in each run names its commit there. The runs of 5 October are in `evidence/` beside this file, byte for byte as copied from the machines.
The scripts here are the latest versions. After the first two runs we only added the `azure-hcl-fresh` mode, per-call
detail for `azure-hcl`, and a fix to `lib-gcloud.sh` (it had reported a failed gcloud command as success). The timing
of every mode the runs use is unchanged.


By Serhii Nikolaichuk (Copyright 2026), contributed under this repository's MIT licence; first published in github.com/nikolaichuk7/tacra-est.
