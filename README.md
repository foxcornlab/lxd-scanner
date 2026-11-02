# `lxd-scanner`

Local triage for `CVE-2026-112816`, the `10.0` certificate-validation flaw in `Canonical LXD` and `MicroCloud`, published `30 October 2026`. Give it a version you own, it tells you whether that install is still open. It never touches the network, never probes a server, never crafts a certificate chain, never sends a payload.

## `The flaw`

`LXD` lets remote clients reach its API over mutual `TLS`: the client presents a certificate, and a trusted client is one whose certificate sits in the server trust store. The server checked every certificate the client attached to the chain, but a `TLS` connection only proves the client owns the private key for the leaf certificate. The rest of the chain is whatever the client chose to attach.

So an attacker with network access to the `HTTPS` API and a trusted client's public certificate, which is not secret, could attach that certificate behind their own and be accepted as that client. Full access to the cluster and its virtual machines follows, and root on the host if the impersonated client is privileged. The `Incus` project, a community fork of `LXD`, reported it; `Canonical` confirmed it hit `LXD` too.

## `What it checks`

- `A version you supply` (`--version 6.9`), for `LXD`, `MicroCloud` or `Incus` (`--product`)
- `This host` (`--local`): `lxd --version`, `microcloud --version` or `incus --version`, falling back to `snap list`
- `An offline inventory` (`--inventory-json inventory.json`): a `JSON` list of `{product, version}` entries, for fleets
- `The full table` (`--list`): every affected range and fixed build in the tool
- `Exposure, separately from version` (`--network-api`): assert `core.https_address` is set, so a vulnerable build is flagged as remotely reachable, not just vulnerable code

A standalone `LXD` server does not expose the `HTTPS` API by default. It listens on a local socket unless an administrator turns it on with `core.https_address`. That is why the tool does not probe: a vulnerable build on a local-socket-only host is still unpatched code, but it is not remotely reachable through this flaw, and the tool says so instead of merging the two.

## `The trap: narrow ranges, and 6.10 is not fixed`

| `Product` | `Affected` | `Fixed in` |
| --- | --- | --- |
| `LXD` | `4.0.14` to before `4.0.15` | `4.0.15` |
| `LXD` | `5.0.10` to before `5.0.11` | `5.0.11` |
| `LXD` | `5.21.8` to before `5.21.9` | `5.21.9` |
| `LXD` | `6.9.0` to before `6.10.1` | `6.10.1` |
| `MicroCloud` | below fixed, lower bound not published | `2.1.5` (`2.x`) / `3.4.1` (`3.x`) |
| `Incus` | below fixed, lower bound not published | `7.6.0` |

Two things to not get wrong. First, `6.10.0` is still vulnerable. It was a fixed build for the September `LXD` flaws, not for this one: the `6.x` fix here is `6.10.1`. A host that upgraded to `6.10` in September and stopped there is still open. Second, a version below the lower bound of its `LXD` branch, `6.8` or `5.21.7` for example, grades `UNKNOWN`, not clean and not vulnerable. The `CNA` record does not list it as affected, and calling it either way would be a guess. `UNKNOWN` is not clean: check the `Canonical` advisory before calling that host fixed.

## `Usage`

```sh
# vulnerable build
python3 lxd_scanner.py --version 6.9

# the trap: 6.10 looks patched, it is not
python3 lxd_scanner.py --version 6.10

# fixed build
python3 lxd_scanner.py --version 6.10.1

# MicroCloud and Incus
python3 lxd_scanner.py --product microcloud --version 3.4.0
python3 lxd_scanner.py --product incus --version 7.5

# on the host itself, with network-API exposure noted
python3 lxd_scanner.py --local

# vulnerable build that is actually reachable
python3 lxd_scanner.py --version 6.9 --network-api

# machine-readable output for fleets
python3 lxd_scanner.py --version 5.21.8 --json

# the full fixed-version table
python3 lxd_scanner.py --list
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean.

## `Snap versus .deb, and the rolling fix`

The vulnerable code is in the snap packages. `Ubuntu` lists its archive (`.deb`) packages of `LXD` as not affected or not shipped for this `CVE`, so `--package deb` reports that position instead of grading the number against a snap table. Do not grade a `.deb` build with snap numbers.

One more snap gotcha, straight from the advisory: the fixed point releases were still rolling out from the candidate channel to stable at disclosure time. A `snap refresh` that reports no updates available does not prove you are patched if your channel had not synced yet. Check the version you actually have after the refresh, with `--local` or `--version`, rather than assuming the fix arrived.

## `Where sources disagree, and what is still unverified`

First, the `GHSA` advisory link carried on the `Ubuntu CVE` page did not resolve when checked for this build, so the fixed table here is corroborated across the `Ubuntu CVE` page (publication `30 October 2026`, description and fixed builds), `The Hacker News` (`1 November 2026`, fixed snap table and `Incus 7.6.0`), and independent `CVE` records carrying the same `CNA` ranges and the `CVSS 4.0 10.0` score with vector `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`. If you hold the advisory itself, confirm the table against it and open an `issue` if anything differs.

Second, `MicroCloud` and `Incus` are graded on a different footing from `LXD`, and the tool does not hide that. The `CNA` record publishes narrow ranges for `LXD` only. For `MicroCloud` (`2.1.5` / `3.4.1`) and `Incus` (`7.6.0`), only the fixed releases are published in the sources checked, with no lower bound, so below-fixed grades `VULNERABLE` as a conservative advisory grade, not as a `CNA` range claim. That is the safe direction for patching, and it is labelled as such in the output.

Third, exploitation: no public sign of use in an attack, not on `CISA KEV`, and the `CISA` assessment dated `30 October 2026` says not known to be exploited. Proof-of-concept repositories for this `CVE` have since appeared on `GitHub`; this tool does not use them, does not link to them, and does not reproduce them. Its job is version triage, not exploitation.

## `Mitigation if you cannot patch today`

Upgrade is the fix; there is no configuration workaround, per both `Canonical` and `Incus`. Until you can upgrade, limit who can reach the `HTTPS` API: this flaw needs network access to it and a trusted client's public certificate, so a local-socket-only install is not remotely reachable through it, and a `MicroCloud` cluster is most exposed while a member is joining, when its public certificate can be captured. Rotate the credentials of any trusted client whose public certificate was exposed to an untrusted network while unpatched: a patch closes the hole, it does not un-expose a certificate.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`18` tests: version parsing, all four `LXD` branches vulnerable and fixed, the `6.10.0` trap, below-lower-bound `UNKNOWN`, unlisted-branch `UNKNOWN`, `MicroCloud` and `Incus` grading, `CLI` exit codes, `JSON` output, the network-API note, the inventory file, the `.deb` position, and the full table count.

## `Thanks to`

- `Canonical`, for the disclosure and the fixed snap releases this tool grades against
- The `Incus` project, for reporting the flaw in the first place
- `Ubuntu` security and `The Hacker News`, whose records corroborated the fixed table while the advisory link did not resolve
- The `CVE` project and `CNA` records, for the affected ranges and the `10.0` score

## `Disclaimer`

Defensive triage only. This tool checks version strings and reports whether an install is below a fixed build. It sends no traffic, probes no server, crafts no certificate chain, and is not a substitute for the vendor advisory. Use it on systems you own or are authorised to audit.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
