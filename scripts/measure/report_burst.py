#!/usr/bin/env python3
"""Times N back-to-back attestation requests in a confidential VM, one at a time, as drill D8 does
(impl/run_drills.py, burst): the cost a protocol pays when every handshake or re-attestation needs fresh Evidence.
Standard library only, so it runs on any guest image as root.

    sudo python3 report_burst.py --mode MODE --n 200 --out result.json

Modes:
  snp-ioctl   /dev/sev-guest. SNP_GET_EXT_REPORT if the first call succeeds, else SNP_GET_REPORT for every call; the
              ioctl is timed with its open and close, as impl/tee.py times it (last_ioctl_ms).
  tsm         configfs-tsm (Linux >= 6.7), one report (SEV-SNP) or quote (TDX) per request; mkdir, inblob, outblob
              and rmdir are timed together.
  vtpm-quote  TPM2_Quote over PCRs 0-7 with a fresh 32-byte nonce, by tpm2-tools. On Azure confidential VMs a
              per-request value reaches the hardware report only through the vTPM (draft-novak-lamps-tacra-est,
              "Nested"). The time includes starting tpm2_quote; --baseline times tpm2_getrandom the same way.
  azure-hcl   Azure confidential VMs: write 64 random bytes to NV index 0x01400002, then read the HCL report from NV
              index 0x01400001; both are timed. Records whether REPORT_DATA of the hardware report changed and whether
              the user data appears in the report, that is whether the paravisor made a new report for the request;
              per call in "detail".
  azure-hcl-fresh  the same write, then reads until the HCL report carries the user data: the wait for a fresh report.

The output carries {"drills": {"D8_report_burst": {...}}} in the layout scripts/measure/burst_stats.py reads.
"""
import argparse
import ctypes
import fcntl
import json
import os
import platform
import socket
import statistics
import subprocess
import tempfile
import time
import uuid

# --- Linux sev-guest UAPI (include/uapi/linux/sev-guest.h), as in impl/tee.py ---------------------------------------
class _Req(ctypes.Structure):
    _fields_ = [("user_data", ctypes.c_ubyte * 64), ("vmpl", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("rsvd", ctypes.c_ubyte * 24)]


class _Resp(ctypes.Structure):
    _fields_ = [("status", ctypes.c_uint32), ("report_size", ctypes.c_uint32),
                ("rsvd", ctypes.c_ubyte * 24), ("report", ctypes.c_ubyte * 4000)]


class _Ioctl(ctypes.Structure):
    _fields_ = [("msg_version", ctypes.c_ubyte), ("req_data", ctypes.c_uint64),
                ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]


class _ExtReq(ctypes.Structure):
    _fields_ = [("data", _Req), ("certs_address", ctypes.c_uint64), ("certs_len", ctypes.c_uint32)]


SNP_GET_REPORT = 0xC0205300
SNP_GET_EXT_REPORT = 0xC0205302
SNP_REPORT_LEN = 1184
CERTS_BUF_LEN = 16384          # the certificate buffer impl/tee.py offers
SEV_GUEST = "/dev/sev-guest"
TSM_REPORT = "/sys/kernel/config/tsm/report"
STALL_MS = 1000.0              # a call above 1 s counts as stalled (scripts/measure/burst_stats.py)
NV_USER_DATA = "0x01400002"    # Azure: user data the paravisor puts in the next HCL report
NV_HCL_REPORT = "0x01400001"   # Azure: the HCL report
HCL_HEADER_LEN = 32            # the HCL report starts with a 32-byte header, then the hardware report
SNP_REPORT_DATA_OFFSET = 0x50  # REPORT_DATA inside the SEV-SNP report (AMD SEV-SNP ABI, Table 22)
REPORT_DATA_LEN = 64
NONCE_LEN = 32
AK_PERSISTENT = "0x81000003"   # Azure's vTPM attestation key, when it is provisioned
FRESH_TIMEOUT_S = 30           # azure-hcl-fresh: give up on one request after this long


def _snp_ioctl(request, io):
    fd = os.open(SEV_GUEST, os.O_RDWR)
    try:
        fcntl.ioctl(fd, request, io)
        return None
    except OSError as e:
        return "errno %d %s" % (e.errno, e.strerror)
    finally:
        os.close(fd)


class SnpIoctl:
    def __init__(self, key_sel):
        self.key_sel = key_sel
        self.use_ext = True
        self.ioctl_used = None
        self.first_ext_error = None

    def once(self, report_data):
        if self.use_ext:
            certs = (ctypes.c_ubyte * CERTS_BUF_LEN)()
            ereq = _ExtReq()
            ctypes.memmove(ereq.data.user_data, report_data, REPORT_DATA_LEN)
            ereq.data.flags = self.key_sel
            ereq.certs_address = ctypes.addressof(certs)
            ereq.certs_len = CERTS_BUF_LEN
            resp = _Resp()
            io = _Ioctl(1, ctypes.addressof(ereq), ctypes.addressof(resp), 0)
            t0 = time.monotonic()
            err = _snp_ioctl(SNP_GET_EXT_REPORT, io)
            ms = (time.monotonic() - t0) * 1000.0
            if err is None and resp.report_size == SNP_REPORT_LEN:
                self.ioctl_used = "SNP_GET_EXT_REPORT"
                return ms
            if self.ioctl_used is None:
                # The first extended request failed: this host does not serve it, so time the plain report.
                self.first_ext_error = "%s exitinfo2=%#x" % (err, io.exitinfo2)
                self.use_ext = False
            else:
                raise RuntimeError("SNP_GET_EXT_REPORT failed mid-burst: %s exitinfo2=%#x" % (err, io.exitinfo2))
        req = _Req()
        ctypes.memmove(req.user_data, report_data, REPORT_DATA_LEN)
        req.flags = self.key_sel
        resp = _Resp()
        io = _Ioctl(1, ctypes.addressof(req), ctypes.addressof(resp), 0)
        t0 = time.monotonic()
        err = _snp_ioctl(SNP_GET_REPORT, io)
        ms = (time.monotonic() - t0) * 1000.0
        if err is not None or resp.report_size != SNP_REPORT_LEN:
            raise RuntimeError("SNP_GET_REPORT failed: %s exitinfo2=%#x" % (err, io.exitinfo2))
        self.ioctl_used = "SNP_GET_REPORT"
        return ms


class Tsm:
    def __init__(self):
        self.provider = None

    def once(self, report_data):
        d = os.path.join(TSM_REPORT, "burst-" + uuid.uuid4().hex[:12])
        t0 = time.monotonic()
        os.mkdir(d)
        try:
            with open(os.path.join(d, "inblob"), "wb") as f:
                f.write(report_data)
            with open(os.path.join(d, "outblob"), "rb") as f:
                out = f.read()
            with open(os.path.join(d, "provider")) as f:
                provider = f.read().strip()
        finally:
            os.rmdir(d)
        ms = (time.monotonic() - t0) * 1000.0
        if not out:
            raise RuntimeError("configfs-tsm returned an empty outblob")
        self.provider = provider
        return ms


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(cmd), (r.stderr or r.stdout).strip()[:400]))
    return r.stdout


class VtpmQuote:
    def __init__(self, workdir):
        self.dir = workdir
        self.ak = None
        self.ak_source = None

    def setup(self):
        handles = _run(["tpm2_getcap", "handles-persistent"])
        if AK_PERSISTENT in handles.lower():
            self.ak, self.ak_source = AK_PERSISTENT, "persistent " + AK_PERSISTENT
            return
        p = lambda n: os.path.join(self.dir, n)
        _run(["tpm2_createprimary", "-C", "e", "-c", p("primary.ctx")])
        _run(["tpm2_create", "-C", p("primary.ctx"), "-G", "ecc", "-u", p("ak.pub"), "-r", p("ak.priv"),
              "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"])
        _run(["tpm2_load", "-C", p("primary.ctx"), "-u", p("ak.pub"), "-r", p("ak.priv"), "-c", p("ak.ctx")])
        self.ak, self.ak_source = p("ak.ctx"), "created under the endorsement hierarchy"

    def once(self, _report_data):
        nonce = os.urandom(NONCE_LEN).hex()
        p = lambda n: os.path.join(self.dir, n)
        t0 = time.monotonic()
        _run(["tpm2_quote", "-c", self.ak, "-l", "sha256:0,1,2,3,4,5,6,7", "-q", nonce,
              "-m", p("q.msg"), "-s", p("q.sig"), "-o", p("q.pcrs"), "-g", "sha256"])
        return (time.monotonic() - t0) * 1000.0


class AzureHcl:
    def __init__(self, workdir):
        self.dir = workdir
        self.prev_report_data = None
        self.report_data_changed = 0
        self.user_data_found = 0
        self.calls = 0
        self.detail = []

    def setup(self):
        r = subprocess.run(["tpm2_nvreadpublic", NV_USER_DATA], capture_output=True, text=True)
        if r.returncode != 0:
            _run(["tpm2_nvdefine", "-C", "o", NV_USER_DATA, "-s", str(REPORT_DATA_LEN), "-a", "ownerread|ownerwrite"])

    def once(self, _report_data):
        ud = os.urandom(REPORT_DATA_LEN)
        udf, hcl = os.path.join(self.dir, "ud.bin"), os.path.join(self.dir, "hcl.bin")
        with open(udf, "wb") as f:
            f.write(ud)
        t0 = time.monotonic()
        _run(["tpm2_nvwrite", "-C", "o", NV_USER_DATA, "-i", udf])
        _run(["tpm2_nvread", "-C", "o", NV_HCL_REPORT, "-o", hcl])
        ms = (time.monotonic() - t0) * 1000.0
        blob = open(hcl, "rb").read()
        off = HCL_HEADER_LEN + SNP_REPORT_DATA_OFFSET
        rd = blob[off:off + REPORT_DATA_LEN]
        self.calls += 1
        changed = self.prev_report_data is not None and rd != self.prev_report_data
        if changed:
            self.report_data_changed += 1
        self.prev_report_data = rd
        found = _has_user_data(blob, ud)
        if found:
            self.user_data_found += 1
        self.detail.append({"i": self.calls, "ms": round(ms, 1), "changed": changed, "found": found})
        return ms


def _has_user_data(blob, ud):
    return ud.hex().encode() in blob.lower() or ud.hex().upper().encode() in blob


class AzureHclFresh(AzureHcl):
    """Write the user data once, then read the HCL report until the user data is in it: the time a protocol waits for
    a fresh hardware report that carries its value. Gives up after FRESH_TIMEOUT_S."""

    def once(self, _report_data):
        ud = os.urandom(REPORT_DATA_LEN)
        udf, hcl = os.path.join(self.dir, "ud.bin"), os.path.join(self.dir, "hcl.bin")
        with open(udf, "wb") as f:
            f.write(ud)
        t0 = time.monotonic()
        _run(["tpm2_nvwrite", "-C", "o", NV_USER_DATA, "-i", udf])
        reads = 0
        while True:
            _run(["tpm2_nvread", "-C", "o", NV_HCL_REPORT, "-o", hcl])
            reads += 1
            if _has_user_data(open(hcl, "rb").read(), ud):
                break
            if time.monotonic() - t0 > FRESH_TIMEOUT_S:
                raise RuntimeError("no HCL report with the user data after %d s (%d reads)" % (FRESH_TIMEOUT_S, reads))
        ms = (time.monotonic() - t0) * 1000.0
        self.calls += 1
        self.user_data_found += 1
        self.detail.append({"i": self.calls, "ms": round(ms, 1), "reads": reads})
        return ms


def baseline(n):
    """Time a cheap TPM command started the same way, to show what starting a tpm2-tools process costs."""
    t = []
    for _ in range(n):
        t0 = time.monotonic()
        _run(["tpm2_getrandom", "8", "--hex"])
        t.append((time.monotonic() - t0) * 1000.0)
    return {"n": n, "median_ms": round(statistics.median(t), 2), "max_ms": round(max(t), 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["snp-ioctl", "tsm", "vtpm-quote", "azure-hcl", "azure-hcl-fresh"], required=True)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--key-sel", type=int, default=0, help="snp-ioctl: 0 lets the firmware choose VCEK or VLEK")
    ap.add_argument("--baseline", type=int, default=0, help="vtpm modes: also time N tpm2_getrandom calls")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="burst-")
    probe = {"snp-ioctl": lambda: SnpIoctl(a.key_sel), "tsm": Tsm,
             "vtpm-quote": lambda: VtpmQuote(work), "azure-hcl": lambda: AzureHcl(work),
             "azure-hcl-fresh": lambda: AzureHclFresh(work)}[a.mode]()
    if hasattr(probe, "setup"):
        probe.setup()

    times, errors = [], []
    t_start = time.monotonic()
    for i in range(a.n):
        try:
            times.append(probe.once(bytes(REPORT_DATA_LEN)))
        except Exception as e:  # keep the burst's partial result: the failure is itself a finding
            errors.append({"index": i + 1, "error": str(e)[:400]})
            break
    total = time.monotonic() - t_start

    burst = {"n": len(times), "requested": a.n, "total_s": round(total, 1), "per_call_ms": [round(t, 2) for t in times],
             "slow_reports": [{"index": i + 1, "ms": round(t, 1)} for i, t in enumerate(times) if t > STALL_MS],
             "errors": errors}
    if times:
        burst.update({"median_ms": round(statistics.median(times), 2), "max_ms": round(max(times), 1),
                      "p95_ms": round(sorted(times)[max(0, int(0.95 * len(times)) - 1)], 2)})
    extra = {}
    if a.mode == "snp-ioctl":
        extra = {"ioctl": probe.ioctl_used, "key_sel": a.key_sel, "first_ext_error": probe.first_ext_error}
    elif a.mode == "tsm":
        extra = {"provider": probe.provider}
    elif a.mode == "vtpm-quote":
        extra = {"ak": probe.ak_source}
    elif a.mode in ("azure-hcl", "azure-hcl-fresh"):
        extra = {"calls": probe.calls, "report_data_changed": probe.report_data_changed,
                 "user_data_found": probe.user_data_found}
        burst["detail"] = probe.detail
    if a.baseline and a.mode in ("vtpm-quote", "azure-hcl", "azure-hcl-fresh"):
        extra["tpm2_getrandom_baseline"] = baseline(a.baseline)

    doc = {"stamp": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), "host": socket.gethostname(),
           "mode": a.mode, "kernel": platform.release(), "probe": extra, "drills": {"D8_report_burst": burst}}
    with open(a.out, "w") as f:
        json.dump(doc, f, indent=1)
    print(json.dumps({"mode": a.mode, "n": burst["n"], "median_ms": burst.get("median_ms"), "max_ms": burst.get("max_ms"),
                      "stalls": len(burst["slow_reports"]), "errors": errors, **extra}))


if __name__ == "__main__":
    main()
