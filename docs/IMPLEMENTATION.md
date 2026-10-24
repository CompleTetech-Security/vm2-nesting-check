# Implementation status

Implemented offline package-version evidence checker, with independent source/semantic review and synthetic local verification on 2026-10-24. The exact documented 3.11.4-3.11.6 affected interval and reviewed 3.11.x fixed line remain explicit. Versions outside that scope stay unknown. An empty interrupted CSV retains a summary row.

Local verification: 13 tests, CLI help, documented synthetic inputs, checksum validation and whitespace checks. Hosted CI must pass for the exact final PR head before merge; a local pass is not a hosted result. The advisory metadata now describes the implemented rule and preserves its original disabled research state under research_origin.

No live traffic, application execution, exploit verification or deployed-target assessment is claimed. Reported fixed versions do not attest installed patches; unknown evidence remains unknown.
