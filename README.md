# vm2-nesting-check

Offline evidence checker for **CVE-2026-92935 — vm2 array-shaped require nesting escape**. Python 3.10+, standard library only. The executable can be copied alone. It never contacts websites, imports application code, runs a package manager, or executes exploit payloads.

```sh
python vm2_nesting_check.py --version 3.11.7 --format json
python vm2_nesting_check.py --inventory examples/inventory.example.json --format html --output report.html
python vm2_nesting_check.py --csv-list inventory.csv --fail-on-finding
python vm2_nesting_check.py --help
python -m unittest -v
```

## Reviewed rules

Primary advisory and reviewed database retrieved 2026-10-24. A public URL cannot provide installed package inventory. Obtain each deployed package instance's exact version and provenance; declarations and local workstation versions are not deployment evidence.

| Example reported version | Result |
| --- | --- |
| 3.11.3 | `unknown` |
| 3.11.4 | `potentially_affected` |
| 3.11.6 | `potentially_affected` |
| 3.11.7 | `fixed_version_reported` |
| 3.11.8 | `fixed_version_reported` |
| 3.12.0 | `unknown` |
| 4.0.0 | `unknown` |

The database maps this CVE to the canonical GHSA; maintainer page still shows no known CVE. Report's September 17 date is not the canonical publication date. Versions below 3.11.4 may have other vulnerabilities but are outside this precise advisory.

The reviewed fixed line is `3.11.x`; future lines remain unknown rather than extrapolating a patch claim. Versions outside the exact affected interval remain unknown, including older releases that might have other flaws. Missing, conflicting, malformed, prerelease, qualified, custom/vendor builds remain unknown. `fixed_version_reported` only describes a version claim; it never attests installed patches or safety. `potentially_affected` is not confirmed exploitability. Every row retains `exploitability: not_tested`.

## Preconditions

| Optional operator observation | Meaning |
| --- | --- |
| `nodevm_nesting_enabled` | NodeVM nesting enabled |
| `require_configuration_is_array_shaped` | require configuration is array-shaped |
| `attacker_supplied_javascript_executed` | attacker-supplied JavaScript executed |

Each observation is boolean or null, is unverified, and never changes the package-version result. Optional source inspection produces separate lexical candidates. No taint analysis, reachability test or runtime evaluation is performed. Absent observations do not establish mitigation.

## Source review candidates

```sh
python vm2_nesting_check.py --source examples/source.example.js --source-root examples --format json
python vm2_nesting_check.py --version 3.11.6 --source examples/source.example.js --source-root examples --format html
```

Select files explicitly with repeatable `--source`; `--source-root` is required
and all selected paths must resolve inside it. Nothing is traversed or executed.
The scanner recognizes simple literal `vm2` CommonJS/ES imports, including
destructuring aliases and namespace `.NodeVM` construction. For each `new`
candidate it records the relative path/line, literal `nesting`, array/object or
literal `require` shape, and a lexical association to `.run()` on a directly
assigned variable. A string argument is not proof of trusted input; a variable
argument is not proof of attacker control. Source rows always have status
`unknown`, exploitability `not_tested` and unfilled operator preconditions.
They never inherit a separately supplied version's assessment.

This is a bounded lexical review aid, not an AST or binding/flow analysis.
Shadowing, reassignment, execution order, computed imports/options, JSX/TS syntax,
templates including interpolation and regex/division ambiguity need manual
review. When no supported match is found, the report includes an unknown
coverage row, never an absence or mitigation verdict. Spreads, duplicate/computed keys, dynamic options
and option expressions exceeding 4,096 tokens keep their shapes unknown.

Source shares the existing 4 MiB/file, 100-file and 10,000-result budgets, with
an additional 200,000-token/file limit. Reports contain relative locations and
shape labels, without source snippets or source string contents. Work from
stable copies; ordinary file checks are not a filesystem sandbox. Selected
source files and their aliases remain protected from `--output --force`.
CSV/JSON report schema 1.1 adds `source_path`, `source_line`, `source_nesting`,
`source_require`, `source_run_argument` and `source_coverage`; HTML includes these
candidates in its evidence notes. Source candidates do not trigger the version
finding gate by themselves.

## Evidence and reports

JSON accepts one object or an array of objects. Required: integer `schema_version: 1`, string `package_version`. Optional: `package: "vm2"`, `label`, `build_source`, and the observation keys above. Unknown or duplicate keys, wrong types, non-finite numbers and malformed inputs are rejected. CSV requires `package_version`; optional columns are label, build_source, and observation keys (`true`, `false`, blank). CLI `--version` is repeatable; values are separate instances, not evidence reconciliation for a single instance. `--build-source` and observation flags (underscore becomes hyphen) apply to CLI versions.

Only regular UTF-8 input files are accepted. Limits: 4 MiB/file, 100 files, 10,000 entries total, 512 characters/text field. Work from stable copies; checks are not a filesystem sandbox. JSON, formula-neutralized CSV and escaped script-free HTML share assessments. Output files publish atomically and do not overwrite existing files without `--force`; inputs remain protected even with force.

Exit 0: completed run; 1: potentially affected with `--fail-on-finding`; 2: argument/input/output error; 130: interrupted, preserving completed observations when possible. Interruption during stdout can leave a truncated document and never appends a second report. Unknown does not count as a finding-gate failure or as a clean result. Reports contain operator data; keep real targets, inventories and reports out of commits.

## Sources and delivery

- https://github.com/patriksimek/vm2/security/advisories/GHSA-8hr7-r645-pc6w
- https://github.com/advisories/GHSA-8hr7-r645-pc6w

[Synthetic report](docs/example-report.html), [reference](docs/REFERENCE.md), [implementation status](docs/IMPLEMENTATION.md), [AGENTS](AGENTS.md), [contribution terms](CONTRIBUTING.md), [security policy](SECURITY.md), [license](LICENSE), [dual licensing](LICENSING.md). Bounded input and reporting helpers are bundled from the reviewed Node.js checker at `74aa57ba5df05c34d17ae67912cd26ec2335201b`, with package-specific range comparison and the mixed-whitespace CSV fix. No companion repository is needed at runtime.

CSV `record_type=result` rows are asset observations. A zero-result report has a `record_type=summary` row carrying completeness, schema, rule date, CVE and `not_tested`; it is not an asset finding.

CSV rejects NUL characters before writing a report. An interruption after a complete report is published preserves that report and exits 130.

If an interrupt leaves file publication indeterminate, the checker exits 130 without retrying. Inspect the output before retrying; the diagnostic does not establish whether publication succeeded.
