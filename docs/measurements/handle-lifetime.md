# The lifetime of a Freshness Handle: how long a report takes, and the host's throttle

Why TACRA says that a Freshness Handle's lifetime MUST leave the Attester time to produce the Evidence that
carries it, and SHOULD NOT be below 60 seconds (draft-novak-rats-tacra, Freshness Kind; the EST profile's
`expires_in`): on a platform that rate-limits attestation requests, the report that carries the Handle can
wait several seconds.

## What was measured

On Google Cloud SEV-SNP (`n2d-standard-2`, EPYC Milan) a report alone takes 7.6–8.2 ms, and when reports are
requested back to back every tenth one waits about 10.2 s: 19 or 20 of 200 in each run, in the runs of
5 October 2026 in `evidence/` beside this file (`snp-ioctl.json`: 19 stalls of 200, median 7.67 ms otherwise;
`tsm.json`: 20 of 200, 7.96 ms) in the run of 13 October 2026 made from this repository (`evidence/20261013T143538Z-gcp-sev-snp-report-rate`:
19 and 20 stalls of 200, 10.23–10.23 s each, 7.96 and 8.0 ms otherwise), and in the five runs of 26 and 30 September 2026 recorded in
github.com/nikolaichuk7/tacra-est (`docs/RESULTS.md`, Section 4, and `drills.json` of each run). On AWS
SEV-SNP (`c6a.large`) there was no stall in 200 requests, 7 ms each; on Google Cloud TDX none, 38.8 ms each;
on Azure under the paravisor a per-request value reaches the hardware report about once per 2 to 3 s
([report-rate.md](report-rate.md)).

## Why every tenth report waits

Section 4.1.7 of the GHCB specification (AMD publication 56421, revision 2.04, January 2025) says that access
to the SNP firmware is "a sequential and synchronous operation", recommends that the hypervisor rate-limit a
guest that issues many Guest Request events, and defines the answer that tells the guest to retry
(SW_EXITINFO2 = 0x0000000200000000). The Linux 7.0 guest driver turns that answer into -EAGAIN, sleeps
SNP_REQ_RETRY_DELAY (2 s) and retries, and gives up with -ETIMEDOUT once more than SNP_REQ_MAX_RETRY_DURATION
(60 s) has passed since the first attempt (`arch/x86/coco/sev/core.c`, `__handle_guest_request`;
`arch/x86/include/asm/sev.h`). A stall of 10.2 s is five such sleeps and the requests between them. Because the
60 s are counted before the last sleep, a report can still arrive about 62 s after the first attempt.

## What follows for a Handle originator

A Handle whose lifetime is shorter than the wait expires while the Attester is still waiting for the report
that carries it, and the second leg is refused for a Handle no `attest-initiate` returned or that has expired
(this server: `internal/tacra/backend.go`, `correlateKey`; the EST profile, Error Handling, 409). The floor of
60 s covers the longest wait measured (10.4 s) with room, and is below the driver's own limit (about 62 s),
which it does not cover: an originator that must cover it sets more. The mock backend of this repository sets
300 s (`internal/mockca/attest.go`, `nonceLifetime`); the bench's Relying Parties refuse a configuration below
60 s.

## What was not measured

The report request alone was timed, in the guest: no network, no appraisal. One run each on AWS, Azure and
Google Cloud TDX, one instance type and region each; bare metal and other hosts may differ. The guest log shows
nothing during a stall: the timing is seen, not the host's reason.

By Serhii Nikolaichuk (Copyright 2026), contributed under this repository's MIT licence; the measurements were
first published in github.com/nikolaichuk7/tacra-est.
