# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Useful in a report: the affected file, what an attacker could do, and steps to reproduce. You will get an answer within a week.

## Scope

- The pipeline scripts in `scripts/` and `tests/runner/`, and the CI workflow in `.github/workflows/`: anything that would let a pull request, a dependency or a downloaded file run code, tamper with the published KQL or coverage layer, or get past a check that should fail.
- The dependency and data pins: a way to make the pipeline consume something other than the pinned version.
- Detection logic: a rule that can be trivially bypassed is a detection gap. Report it like a bug (a public issue is fine) unless it reveals something sensitive.

Out of scope: vulnerabilities in third-party projects used here (pySigma, Zircolite, the EVTX sample set, ATT&CK data). Report those upstream. The known, accepted finding PYSEC-2026-2447 (diskcache) is documented in `docs/decisions.md`, decision 7.
