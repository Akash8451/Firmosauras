"""Group 2 static-analysis logic (Task 8).

The router handler ``analysis.py`` is a thin I/O wrapper; the real work lives here
as pure, unit-testable modules:

  * ``strings_extract`` — multi-encoding (ASCII + UTF-16LE/BE) string extraction;
  * ``entropy``         — per-section Shannon entropy (flag packed/encrypted);
  * ``secrets``         — a regex pass OVER THE SAME extracted strings (reuse, not
    a second extraction pipeline — analysis-modules-rbac.md);
  * ``hardening``       — NX / PIE / RELRO / stack-canary flags via ELF parsing;
  * ``versions``        — component version candidates per family;
  * ``analyze``         — assembles the ``firmware.analyzed`` payload.
"""
