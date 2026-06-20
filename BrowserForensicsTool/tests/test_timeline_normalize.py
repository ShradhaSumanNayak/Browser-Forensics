import datetime

import pandas as pd

from reports.timeline_generator import TimelineGenerator


def test_normalize_seconds_epoch():
    g = TimelineGenerator(".")
    sec = 1609459200  # 2021-01-01 00:00:00 UTC
    ts = g._normalize_time(sec)
    assert isinstance(ts, pd.Timestamp)
    assert ts == pd.Timestamp(datetime.datetime.utcfromtimestamp(sec))


def test_normalize_milliseconds_epoch():
    g = TimelineGenerator(".")
    ms = 1609459200000  # 2021-01-01 00:00:00 UTC in ms
    ts = g._normalize_time(ms)
    assert isinstance(ts, pd.Timestamp)
    assert ts == pd.Timestamp(datetime.datetime.utcfromtimestamp(ms / 1000.0))


def test_normalize_webkit_microseconds():
    g = TimelineGenerator(".")
    # choose a known datetime and compute WebKit-style microseconds since 1601-01-01
    dt = datetime.datetime(2022, 1, 2, 3, 4, 5)
    webkit_us = int((dt - datetime.datetime(1601, 1, 1)).total_seconds() * 1_000_000)
    ts = g._normalize_time(webkit_us)
    assert isinstance(ts, pd.Timestamp)
    # compare core components to avoid timezone issues
    t_dt = ts.to_pydatetime()
    assert (t_dt.year, t_dt.month, t_dt.day, t_dt.hour, t_dt.minute, t_dt.second) == (
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
    )


def test_normalize_iso_and_datetime():
    g = TimelineGenerator(".")
    s = "2023-04-05 06:07:08"
    ts1 = g._normalize_time(s)
    assert isinstance(ts1, pd.Timestamp)
    assert ts1 == pd.Timestamp("2023-04-05 06:07:08")

    dt = datetime.datetime(2020, 12, 31, 23, 59, 59)
    ts2 = g._normalize_time(dt)
    assert isinstance(ts2, pd.Timestamp)
    assert ts2 == pd.Timestamp(dt)
