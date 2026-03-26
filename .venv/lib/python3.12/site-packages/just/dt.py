from ciso8601 import parse_datetime as parse_dt
from datetime import datetime, timedelta, timezone


def utcnow(**kwargs):
    if kwargs:
        return datetime.now(timezone.utc) + timedelta(**kwargs)
    return datetime.now(timezone.utc)
