#!/usr/bin/env python3
"""Detection-only local triage for CVE-2026-112816, improper
certificate validation in the HTTPS listener in Canonical LXD
and MicroCloud (CVSS 4.0 10.0, published 2026-10-30).

The flaw: LXD checked every certificate a client attached to its
TLS chain against the trust store, but a TLS connection only
proves the client owns the private key for the leaf certificate.
An attacker with network access to the HTTPS API and a trusted
client's public certificate (which is not secret) could attach
that certificate behind their own and be accepted as that client,
gaining full access to the cluster and its virtual machines, and
root on the host if the impersonated client is privileged. The
Incus project, a community fork of LXD, reported the flaw;
Canonical confirmed it affected LXD as well.

This tool never touches the network, never probes a server, never
sends a payload and never crafts a certificate chain. It grades
a version you supply, one it reads on this host, or an inventory
list, against the fixed-version table. Remote version
fingerprinting is not attempted: a standalone LXD server does not
expose the HTTPS API by default (local Unix socket only, unless
core.https_address is set), and a version string is the reliable
local signal.

Grading, and the two traps in it:

1. LXD is graded against the CNA record's narrow ranges, not
   against "anything below the fixed build". The record lists
   4.0.14 before 4.0.15, 5.0.10 before 5.0.11, 5.21.8 before
   5.21.9, and 6.9.0 before 6.10.1. So a version below the lower
   bound of its branch (for example 6.8, or 5.21.7) grades
   UNKNOWN, not clean and not vulnerable: the record does not
   list it as affected, and calling it either way would be a
   guess. Versions at or above the fixed build grade FIXED.
2. 6.10.0 is still vulnerable. It was a fixed build for the
   September 2026 LXD flaws, but for this CVE the 6.x fix is
   6.10.1, not 6.10. A host that upgraded to 6.10 in September
   and stopped there is still open.

MicroCloud and Incus are graded differently, and the README says
so plainly: Canonical's fixed releases are published (MicroCloud
3.4.1 and 2.1.5, Incus 7.6.0) but no CNA lower bound is published
for either, so below-fixed grades VULNERABLE as a conservative
advisory grading, not as a CNA range claim. A MicroCloud or Incus
version outside the 2.x / 3.x (MicroCloud) majors grades UNKNOWN.

Ubuntu archive (.deb) packages of LXD are listed by Ubuntu as
not affected or not shipped; the vulnerable code is in the snap
packages. This tool grades snap versions by default. If you pass
--package deb, it reports the Ubuntu archive position instead of
grading the number, because a snap version table does not apply
to a .deb build.

Exploitation status, as of 2026-11-02: no public sign of use in
an attack, not on CISA KEV, CISA assessment dated 2026-10-30
says not known to be exploited, and no working exploit had been
published at disclosure time. That is a statement about what was
reported, not a reason to wait: a 10.0 authentication bypass with
fixed builds available does not need a long fuse, and proof-of-
concept repositories have since appeared. This tool grades
exposure, it does not claim exploitation.

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable
finding, 1 = scan error. UNKNOWN does not change the exit code,
but it is not clean.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys

VULNERABLE = "VULNERABLE"
FIXED_VERDICT = "FIXED"
UNKNOWN = "UNKNOWN"

# LXD: (lower bound, fixed build) per branch, from the CNA record.
# Versions below the lower bound grade UNKNOWN, not clean.
LXD_RANGES = {
    (4, 0): ((4, 0, 14), (4, 0, 15)),
    (5, 0): ((5, 0, 10), (5, 0, 11)),
    (5, 21): ((5, 21, 8), (5, 21, 9)),
    (6,): ((6, 9, 0), (6, 10, 1)),
}

# MicroCloud: major -> fixed build. No lower bound published, so
# below-fixed is a conservative advisory grade (see module docstring).
MICROCLOUD_FIXED = {
    2: (2, 1, 5),
    3: (3, 4, 1),
}

# Incus: fixed build only, same caveat as MicroCloud.
INCUS_FIXED = (7, 6, 0)

CVE = "CVE-2026-112816"


def parse_version(raw):
    """Parse a version string like '6.9', '6.10.1' or 'v5.21.8'.

    Accepts an optional leading 'v' and trailing build suffixes
    after a space or dash. Returns a 3-tuple, or None.
    """
    if raw is None:
        return None
    text = str(raw).strip().lstrip("vV")
    if not text:
        return None
    text = text.split()[0].split("-")[0]
    parts = text.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    nums = tuple(int(p) for p in parts)
    while len(nums) < 3:
        nums = nums + (0,)
    return nums[:3]


def fmt_version(version):
    return ".".join(str(n) for n in version)


def _grade_range(version, lower, fixed, product):
    if version < lower:
        return {
            "version": fmt_version(version),
            "verdict": UNKNOWN,
            "detail": (
                "%s %s is below the CNA record's affected range for "
                "its branch (affected from %s); the record does not "
                "list it as affected, so it is neither clean nor "
                "vulnerable on this evidence" % (
                    product, fmt_version(version), fmt_version(lower))
            ),
            "fixed": fmt_version(fixed),
        }
    if version < fixed:
        return {
            "version": fmt_version(version),
            "verdict": VULNERABLE,
            "detail": (
                "%s %s is in the affected range (%s to before %s); "
                "upgrade to %s" % (
                    product, fmt_version(version), fmt_version(lower),
                    fmt_version(fixed), fmt_version(fixed))
            ),
            "fixed": fmt_version(fixed),
        }
    return {
        "version": fmt_version(version),
        "verdict": FIXED_VERDICT,
        "detail": "%s %s is at or above the fixed build %s" % (
            product, fmt_version(version), fmt_version(fixed)),
        "fixed": fmt_version(fixed),
    }


def _grade_below_fixed(version, fixed, product, caveat):
    if version < fixed:
        return {
            "version": fmt_version(version),
            "verdict": VULNERABLE,
            "detail": (
                "%s %s is below the fixed build %s; upgrade to %s"
                % (product, fmt_version(version), fmt_version(fixed),
                   fmt_version(fixed))
            ),
            "fixed": fmt_version(fixed),
            "notes": [caveat],
        }
    return {
        "version": fmt_version(version),
        "verdict": FIXED_VERDICT,
        "detail": "%s %s is at or above the fixed build %s" % (
            product, fmt_version(version), fmt_version(fixed)),
        "fixed": fmt_version(fixed),
        "notes": [caveat],
    }


def grade(product, version):
    """Grade one parsed version for one product.

    product is 'lxd', 'microcloud' or 'incus'. Returns a result
    dict with version, verdict, detail, fixed and notes.
    """
    product = (product or "lxd").lower()
    if version is None:
        return {
            "version": None, "verdict": UNKNOWN,
            "detail": "unparseable version string",
            "fixed": None, "notes": [],
        }
    if product == "lxd":
        branch = version[:2] if version[0] != 6 else (6,)
        if branch not in LXD_RANGES:
            return {
                "version": fmt_version(version), "verdict": UNKNOWN,
                "detail": (
                    "LXD branch %s is not in the CNA affected ranges "
                    "(4.0, 5.0, 5.21, 6.x from 6.9); check the "
                    "Canonical advisory before calling this host "
                    "fixed" % ".".join(str(n) for n in branch)
                ),
                "fixed": None, "notes": [],
            }
        lower, fixed = LXD_RANGES[branch]
        result = _grade_range(version, lower, fixed, "LXD")
        result["notes"] = []
        return result
    if product == "microcloud":
        major = version[0]
        if major not in MICROCLOUD_FIXED:
            return {
                "version": fmt_version(version), "verdict": UNKNOWN,
                "detail": (
                    "MicroCloud major %s has no fixed build in this "
                    "tool's table (2.x and 3.x only); check the "
                    "Canonical advisory" % major
                ),
                "fixed": None, "notes": [],
            }
        return _grade_below_fixed(
            version, MICROCLOUD_FIXED[major], "MicroCloud",
            "MicroCloud lower bound not published in the CNA record; "
            "below-fixed is a conservative advisory grade, not a CNA "
            "range claim.")
    if product == "incus":
        return _grade_below_fixed(
            version, INCUS_FIXED, "Incus",
            "Incus lower bound not published in the CNA record; "
            "below-fixed is a conservative advisory grade, not a CNA "
            "range claim.")
    return {
        "version": fmt_version(version), "verdict": UNKNOWN,
        "detail": "unknown product %r; use lxd, microcloud or incus" % product,
        "fixed": None, "notes": [],
    }


def run_capture(argv):
    try:
        out = subprocess.run(argv, capture_output=True, text=True,
                             timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def read_local():
    """Best-effort local detection on this host. No network.

    Returns (product, raw_version, source, network_api) or
    (None, None, None, None) when nothing is found. network_api
    is True only when `lxc config get core.https_address` returns
    a non-empty value; None means it could not be determined.
    """
    for product, binary in (("lxd", "lxd"), ("microcloud", "microcloud"),
                            ("incus", "incus")):
        if shutil.which(binary) is None:
            continue
        raw = run_capture([binary, "--version"])
        if raw:
            first = raw.splitlines()[0].strip()
            network_api = None
            if product in ("lxd", "incus"):
                addr = run_capture(["lxc", "config", "get",
                                    "core.https_address"])
                if addr is not None:
                    network_api = bool(addr)
            return product, first, "%s --version on this host" % binary, network_api
    snap = run_capture(["snap", "list"])
    if snap:
        for line in snap.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 2 and fields[0] in ("lxd", "microcloud"):
                return fields[0], fields[1], "snap list on this host", None
    return None, None, None, None


def find_inventory(entries, product):
    """Pick an entry for `product` from an inventory list.

    Entries are dicts with product/name and version keys.
    Returns (raw_version, source) or (None, None).
    """
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("product") or entry.get("name") or "").lower()
        version = entry.get("version")
        if name == product and version:
            return str(version), "inventory entry: %s" % name
    return None, None


def render_text(result):
    lines = []
    lines.append("cve: %s" % CVE)
    lines.append("product: %s" % result.get("product", "?"))
    lines.append("version: %s" % (result.get("version") or "?"))
    if result.get("source"):
        lines.append("source: %s" % result["source"])
    lines.append("verdict: %s (%s)" % (result["verdict"], result["detail"]))
    if result.get("fixed"):
        lines.append("fixed: %s" % result["fixed"])
    if result.get("network_api") is True:
        lines.append("Note: network HTTPS API is on (core.https_address "
                     "is set): a vulnerable build here is remotely "
                     "reachable via this flaw, not just vulnerable code.")
    elif result.get("network_api") is False:
        lines.append("Note: network HTTPS API not detected on this host: "
                     "a vulnerable build is still unpatched code, but "
                     "this flaw needs the network API to be reachable.")
    for note in result.get("notes", []):
        lines.append("Note: %s" % note)
    return "\n".join(lines)


def table():
    return [
        {"product": "lxd", "affected": "4.0.14 to before 4.0.15",
         "fixed": "4.0.15"},
        {"product": "lxd", "affected": "5.0.10 to before 5.0.11",
         "fixed": "5.0.11"},
        {"product": "lxd", "affected": "5.21.8 to before 5.21.9",
         "fixed": "5.21.9"},
        {"product": "lxd", "affected": "6.9.0 to before 6.10.1",
         "fixed": "6.10.1"},
        {"product": "microcloud", "affected": "below fixed (lower bound not published)",
         "fixed": "2.1.5 (2.x) / 3.4.1 (3.x)"},
        {"product": "incus", "affected": "below fixed (lower bound not published)",
         "fixed": "7.6.0"},
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only LXD / MicroCloud CVE-2026-112816 triage.")
    parser.add_argument("--product", default="lxd",
                        choices=["lxd", "microcloud", "incus"],
                        help="Product to grade (default: lxd)")
    parser.add_argument("--version", help="Installed version, e.g. 6.9 or 5.21.8")
    parser.add_argument("--local", action="store_true",
                        help="Read the installed version on this host (binary --version or snap list)")
    parser.add_argument("--inventory-json", metavar="PATH",
                        help="JSON list of {product, version} entries to grade")
    parser.add_argument("--package", default="snap", choices=["snap", "deb"],
                        help="Package form: snap (graded) or deb (Ubuntu archive position)")
    parser.add_argument("--network-api", action="store_true",
                        help="Assert the network HTTPS API is on (core.https_address set)")
    parser.add_argument("--list", action="store_true",
                        help="Print the fixed-version table and exit")
    parser.add_argument("--json", action="store_true",
                        help="Machine-readable JSON output")
    args = parser.parse_args(argv)

    if args.list:
        rows = table()
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                print("%s | affected %s | fixed %s" % (
                    row["product"], row["affected"], row["fixed"]))
        return 0

    if args.package == "deb":
        result = {
            "product": args.product, "version": args.version,
            "verdict": "NOT_AFFECTED_PER_UBUNTU",
            "detail": (
                "Ubuntu lists its archive (.deb) packages of LXD as "
                "not affected or not shipped for CVE-2026-112816; "
                "the vulnerable code is in the snap packages, so a "
                "snap version table does not grade a .deb build"
            ),
            "fixed": None, "notes": [],
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(render_text(result))
        return 0

    raw = args.version
    source = None
    network_api = True if args.network_api else None
    if args.local:
        product, raw, source, detected = read_local()
        if raw is None:
            print("error: no lxd, microcloud or incus install found on "
                  "this host; pass --version instead", file=sys.stderr)
            return 1
        args.product = product
        if network_api is None:
            network_api = detected
    elif args.inventory_json:
        try:
            with open(args.inventory_json) as handle:
                entries = json.load(handle)
        except (OSError, ValueError) as exc:
            print("error: cannot read inventory JSON: %s" % exc,
                  file=sys.stderr)
            return 1
        raw, source = find_inventory(entries, args.product)
        if raw is None:
            print("error: no %s entry in %s; pass --version instead"
                  % (args.product, args.inventory_json), file=sys.stderr)
            return 1
    elif not raw:
        parser.print_usage(sys.stderr)
        print("error: pass --version, --local, or --inventory-json",
              file=sys.stderr)
        return 1

    result = grade(args.product, parse_version(raw))
    result["product"] = args.product
    if source:
        result["source"] = source
    if network_api is not None:
        result["network_api"] = network_api
    if result["verdict"] == UNKNOWN and result["version"] is None:
        print("error: unparseable version %r" % raw, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))

    return 2 if result["verdict"] == VULNERABLE else 0


if __name__ == "__main__":
    raise SystemExit(main())
