"""Phase 4: explainable, rule-based detection over audit logs (goals 6, 7, 8).

No model, no weights, no learning. Every alert is a rule applied to counts and
compares that a judge can re-derive by hand from the log.

* goal 6 -- :mod:`privilege`: a privilege change is suspicious when approved
  context does not cover it (subject, operation, role, scope, window, signer);
* goal 7 -- :mod:`lateral`: first-seen service edges and chains for one identity,
  against a baseline built from that identity's own history;
* goal 8 -- :mod:`timing`: per-source clock correction with an explicit
  uncertainty, and ``order="uncertain"`` instead of a guess when the error bars
  overlap.

Entry point: :func:`core.run` for a whole log, and the ``detect_*`` ops in
``team_app.py`` for the adapter.
"""

from .alerts import Alert
from .config import ConfigError, DetectorConfig, load
from .core import REPORT_VERSION, DetectionReport, run, run_bytes

__all__ = [
    "Alert", "ConfigError", "DetectionReport", "DetectorConfig", "REPORT_VERSION",
    "load", "run", "run_bytes",
]
