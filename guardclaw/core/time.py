"""
guardclaw/core/time.py

THE ONLY TIMESTAMP FUNCTION IN GUARDCLAW.

GEF Wire Format: YYYY-MM-DDTHH:MM:SS.mmmZ
                 (milliseconds, explicit Z, no +00:00, no microseconds)

Every module that needs a timestamp imports gef_timestamp() from here.
Nothing else. No datetime.now().isoformat(). No utc_now(). Only this.
"""

from datetime import datetime, timezone


def gef_timestamp() -> str:
    """
    Return current UTC time in GEF wire format.
    Format: YYYY-MM-DDTHH:MM:SS.mmmZ  (exactly 3 fractional digits, Z suffix)
    """
    now = datetime.now(timezone.utc)
    ms  = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
