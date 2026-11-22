"""Manual live check of the TinyFish client: ONE real, read-only call. It spends credits, so a person runs it, never a test.

    source ~/.airlock-env          # exports TINYFISH_API_KEY (and anything else you keep there)
    AIRLOCK_TINYFISH=1 python3 gateway/scripts/tinyfish_smoke.py

It asks TinyFish for the top 3 titles on news.ycombinator.com, through the same validation, client, timeout and
"untrusted content" wrapping the gateway uses. It prints PASS or FAIL and a short excerpt of the result, never the key.
Until this has passed, the live TinyFish path is UNTESTED (everything else uses the mock client).
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from airlock.tinyfish import HttpTinyFish, WebTasks  # noqa: E402
from airlock.tools import parse_web_task  # noqa: E402

URL = "https://news.ycombinator.com/"
GOAL = "Read only. Return the titles of the top 3 stories on the front page as a JSON list of strings."


def main() -> int:
    if os.getenv("AIRLOCK_TINYFISH", "").strip().lower() not in ("1", "true", "yes", "on"):
        print("FAIL: set AIRLOCK_TINYFISH=1 to confirm you want a real call (it spends credits)")
        return 2
    key = os.getenv("TINYFISH_API_KEY", "").strip()
    if not key:
        print("FAIL: TINYFISH_API_KEY is not set (source ~/.airlock-env first)")
        return 2
    parsed, problem = parse_web_task({"url": URL, "goal": GOAL})
    if parsed is None:
        print(f"FAIL: our own validation refused the smoke request: {problem}")
        return 1
    res = asyncio.run(WebTasks(HttpTinyFish(key), max_runs=1, timeout=90.0).run(parsed["url"], parsed["goal"]))
    shown = res.output.replace(key, "<hidden>")  # belt and braces: the client never puts the key in a result
    if res.ok and "[UNTRUSTED WEB CONTENT" in res.output and len(res.output) > 120:
        print("PASS: one live run completed; result (untrusted, shortened):")
        print(shown[:600])
        return 0
    print("FAIL: " + shown[:300])
    return 1


if __name__ == "__main__":
    sys.exit(main())
