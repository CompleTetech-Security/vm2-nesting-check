<p align="center">
  <img src="docs/images/banner.png" alt="vm2-nesting-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-research%20only-B45309" alt="Status: research only">
  <img src="https://img.shields.io/badge/checker-pending-B45309" alt="Checker: pending">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

<p align="center">
  <b>Planned checker for the vm2 array-shaped require nesting escape</b><br>
  CVE-2026-92935 · GHSA-8hr7-r645-pc6w · research only, no checker yet
</p>

---

> **Repository initialized; checker implementation pending.**
> This project currently contains research and an implementation checklist.
> It does not assess systems or provide an executable detection rule.

`vm2-nesting-check` is dedicated to **CVE-2026-92935**, an escape in the [vm2](https://github.com/patriksimek/vm2) Node.js sandbox that applies when `NodeVM` nesting is enabled with an array-shaped `require` configuration. The planned checker will follow the evidence conventions of [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check): it will send **no exploit payloads** and report uncertainty honestly. None of that exists yet.

## Status and what's planned

There are currently no checker commands, downloadable binaries, install steps, test results, or CI. Follow progress in the exploit-specific [implementation checklist](docs/IMPLEMENTATION.md), and read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) before contributing.

## One exploit, one repository

| Field | Scope |
| --- | --- |
| Exploit identifier | `CVE-2026-92935` |
| Aliases for this same exploit | `GHSA-8hr7-r645-pc6w` |
| Research verification date | 2026-10-23 |
| Implementation state | `planned` |
| Detection rule | **Disabled — research only** |

This repository is dedicated to **CVE-2026-92935**. Aliases and multiple affected
products identify this same exploit; they do not create additional scanner scopes.
Future fixes for different vulnerabilities belong in independent repositories.

## Planned report layout

A future checker is intended to produce human-readable findings plus machine-readable JSON/CSV. The image below is an **illustration of a possible layout only**; no report generator exists.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Illustrative placeholder report layout, clearly marked as not implemented" width="900">
  </picture>
</p>

<p align="center"><sub>ILLUSTRATIVE mock-up with placeholder rows and reserved <code>example.*</code> domains. It is not output from a checker and shows no real results.</sub></p>

## What the results will mean (planned)

This is the planned status vocabulary from [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md). It is not implemented.

| Status | Planned meaning |
| --- | --- |
| `potentially_affected` | Evidence matches this advisory's documented range or condition. Not confirmed exploitability. |
| `fixed_version_reported` | A supported comparison shows a version at or above the reported fix. Not a verified clean bill of health. |
| `unknown` | Missing, malformed, conflicting, prerelease, vendor/custom-build, possible-backport, or uncovered versions. |

| Research-only version data | Value |
| --- | --- |
| **Affected (per advisory)** | `>=3.11.4 <=3.11.6` |
| **Fixed in (reported)** | `3.11.7` |

These values come from [advisory.json](advisory.json) and are research only; no detection rule is enabled. Versions below 3.11.4 may have other vulnerabilities but are outside this precise advisory.

> [!IMPORTANT]
> **Potential exposure is not confirmed exploitability.** Exploitability stays `not_tested`. A reported fix version is evidence, not a guarantee that a deployed system is patched, and none of this is implemented yet.

## How it will work (planned)

- Prefer offline version, inventory, or configuration evidence appropriate to this exploit.
- Keep version state, documented preconditions, evidence provenance, and uncertainty separate.
- Preserve `exploitability: not_tested`; never run exploit payloads or confirm compromise.
- Keep missing, malformed, conflicting, vendor-qualified, prerelease, and uncovered versions `unknown`.
- Produce human-readable findings and machine-readable JSON/CSV; document each output before release.
- Add bounded, explicitly selected passive network behavior only if it provides useful evidence.

These capabilities are **planned**, not implemented.

## Advisory snapshot

The following is source-backed research for implementation planning. It is not a
test result, a live rule feed, or an attestation that a deployed system is patched.

### Affected versions or conditions

>=3.11.4 <=3.11.6

### Reported fixes or remediation

3.11.7

### Deployment preconditions to establish

- NodeVM nesting enabled
- require configuration is array-shaped
- attacker-supplied JavaScript executed

### Evidence notes and limitations

- The database maps this CVE to the canonical GHSA; maintainer page still shows no known CVE. Report's September 17 date is not the canonical publication date. Versions below 3.11.4 may have other vulnerabilities but are outside this precise advisory.

## Primary sources

1. [github.com](https://github.com/patriksimek/vm2/security/advisories/GHSA-8hr7-r645-pc6w)
2. [github.com](https://github.com/advisories/GHSA-8hr7-r645-pc6w)

The research date records the supplied verification snapshot. Recheck primary
advisories before enabling any detection logic, and retain contradictory evidence.

## Documentation

- [Implementation checklist](docs/IMPLEMENTATION.md): the local work plan and verification gates
- [advisory.json](advisory.json): source-preserving research record (detection disabled)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Repository instructions](AGENTS.md)

## License

[AGPL-3.0](LICENSE), or a separate commercial agreement with CompleteTech LLC.
See [LICENSING.md](LICENSING.md) and the
[contribution terms](CONTRIBUTING.md#licensing-of-contributions).
Names and branding are governed by [BRAND_ASSETS.md](BRAND_ASSETS.md).

<p align="center">
  <sub>Built by <a href="https://complete.tech">CompleteTech LLC</a></sub><br>
  <sub>Copyright © 2026 CompleteTech LLC.</sub>
</p>
