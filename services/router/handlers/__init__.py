"""Handler package. Importing it registers every stage handler via the
`@register(topic)` decorator side-effects — this is what `runner.py` relies on
(no shared handler dict).

Ownership (CODEOWNERS): triage/unpack/analysis -> Group 2;
cve_match/aggregate -> Group 3. Group 1 seeds these as stubs.
"""
from . import triage, unpack, analysis, cve_match, aggregate  # noqa: F401
