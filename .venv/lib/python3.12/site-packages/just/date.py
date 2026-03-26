from datetime import datetime, timedelta

from dateutil.rrule import DAILY, rrule


def yesterday(days_extra=0):
    return datetime.now() - timedelta(days=1 + days_extra)


def days_back(n, exclude_today=False, utc=True):
    today = datetime.utcnow() if utc else datetime.today()
    res = [d.date() for d in rrule(DAILY, dtstart=today - timedelta(days=n - 1), until=today)]
    if exclude_today:
        res = res[:-1]
    return res
