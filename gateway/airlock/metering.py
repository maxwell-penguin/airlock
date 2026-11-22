"""Token metering for model clients. Layer 1 support (the agent's budget), shared by scripts/llm_eval.py and standing tasks.

MeteredClient wraps an Anthropic-style client: it counts tokens from each response's `usage`, caps max_tokens per call, and refuses the
next call once the budget is spent (BudgetExceeded). LLMAgent turns that refusal into a normal end of the run.
"""
from __future__ import annotations


class BudgetExceeded(Exception):
    pass


class MeteredClient:
    def __init__(self, inner, budget_tokens: int, max_tokens: int):
        self.inner, self.budget, self.max_tokens = inner, budget_tokens, max_tokens
        self.input_tokens = self.output_tokens = self.calls = 0
        self.exhausted = False
        self.messages = self  # the agent calls client.messages.create(...)

    @property
    def used(self) -> int:
        return self.input_tokens + self.output_tokens

    async def create(self, **kw):
        if self.used >= self.budget:
            self.exhausted = True
            raise BudgetExceeded()
        kw["max_tokens"] = min(int(kw.get("max_tokens", self.max_tokens)), self.max_tokens)  # a hard cap per call, whatever the caller asks
        resp = await self.inner.messages.create(**kw)
        self.calls += 1
        usage = getattr(resp, "usage", None)
        if usage is not None:
            self.input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
            self.output_tokens += int(getattr(usage, "output_tokens", 0) or 0)
        else:  # no usage reported: count a conservative guess so the budget still bites
            self.output_tokens += kw["max_tokens"]
            self.input_tokens += 2000
        if self.used >= self.budget:
            self.exhausted = True
        return resp
