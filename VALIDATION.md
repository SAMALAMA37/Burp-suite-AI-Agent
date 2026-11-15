# Publication preparation validation

Checked on Windows on 2026-11-15, using Python 3.12 from the development runtime.

| Check | Result |
| --- | --- |
| Python unittest discovery (`test_*.py`) | 300 tests: 294 passed, 2 failed, 4 errored |
| Document viewer DOM tests | Passed |
| Connection Hub and router priority DOM tests | Passed |
| Source packaging | Built from reviewed non-ignored files |
| Common credential-pattern scan | No matches; not an exhaustive secret audit |
| GitHub upload | Not performed: signed out, credentials unavailable, and Git index writes denied |
| Live Burp loading and providers | Not performed in this preparation run |

The Python rerun used a short workspace temporary directory. The initial run additionally encountered Windows temporary-path failures; those disappeared with the shorter path. The six remaining cases require local HTTP fixtures: four embedding-protocol tests and two provider-hub transport tests. The environment denied socket connections (WinError 10013), producing connection errors and downstream assertion failures. These cases still need a passing run outside this restricted environment.

The CI definition has been prepared but has not run on GitHub. Do not describe this source package as a fully validated release until CI and a manual Burp load pass. No project-wide license has been selected.
