"""AIRLOCK_TINYFISH_WINDOW_SECONDS: an optional rolling window for the web task cap. OFF by default: then the per-process cap is
exactly what it always was. Mock TinyFish only, a fake clock, no sleeping."""
from airlock.config import Settings, load_settings
from airlock.tinyfish import MockTinyFish, WebTasks, build_web_tasks

from .conftest import run

URL, GOAL = "https://news.example.com/", "Read only. Titles."


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def runs(wt, n):
    return [run(wt.run(URL, GOAL)).ok for _ in range(n)]


def test_off_by_default_the_cap_is_per_process_and_never_resets():
    clock = Clock()
    wt = WebTasks(MockTinyFish(), max_runs=2, clock=clock)
    assert runs(wt, 2) == [True, True]
    clock.t += 10 ** 6                                   # a very long time later
    assert runs(wt, 1) == [False] and "limit for this session" in wt.refusal()


def test_with_a_window_old_runs_stop_counting():
    clock = Clock()
    wt = WebTasks(MockTinyFish(), max_runs=2, window_seconds=60, clock=clock)
    assert runs(wt, 2) == [True, True]
    assert runs(wt, 1) == [False]                        # still inside the window
    assert "2 runs per 60" in wt.refusal()
    clock.t += 61
    assert wt.refusal() is None and runs(wt, 2) == [True, True] and runs(wt, 1) == [False]


def test_the_window_slides_it_is_not_a_fixed_bucket():
    clock = Clock()
    wt = WebTasks(MockTinyFish(), max_runs=2, window_seconds=100, clock=clock)
    runs(wt, 1)
    clock.t += 60
    runs(wt, 1)
    clock.t += 50                                        # the first run is 110 s old, the second 50 s: one slot free
    assert runs(wt, 2) == [True, False]


def test_the_window_never_allows_more_than_max_runs_at_once_and_one_at_a_time_still_holds():
    wt = WebTasks(MockTinyFish(), max_runs=1, window_seconds=3600)
    assert runs(wt, 3) == [True, False, False]
    wt._busy = True
    assert "one at a time" in wt.refusal()


def test_a_bad_window_means_off_not_unlimited():
    for bad in (0, -5, float("nan"), float("inf"), 10 ** 9, "60", True, None):
        wt = WebTasks(MockTinyFish(), max_runs=1, window_seconds=bad)
        assert wt.window_seconds is None
        assert runs(wt, 2) == [True, False]


def test_the_setting_comes_from_the_environment_and_a_bad_value_keeps_it_off(monkeypatch):
    monkeypatch.delenv("AIRLOCK_TINYFISH_WINDOW_SECONDS", raising=False)
    assert load_settings().tinyfish_window_seconds is None
    for raw, want in (("3600", 3600.0), ("0", None), ("-1", None), ("abc", None), ("nan", None), ("99999999", None), ("", None)):
        monkeypatch.setenv("AIRLOCK_TINYFISH_WINDOW_SECONDS", raw)
        assert load_settings().tinyfish_window_seconds == want, raw


def test_build_web_tasks_passes_the_window_on_and_defaults_to_off():
    assert build_web_tasks(Settings(tinyfish="mock")).window_seconds is None
    assert build_web_tasks(Settings(tinyfish="mock", tinyfish_window_seconds=120.0)).window_seconds == 120.0
