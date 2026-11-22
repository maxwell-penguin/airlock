"""Sandbox backends. Layer 5 (containment).
MockSandbox works today; DockerSandbox was run against a live Docker daemon (tests skip without one).
Invariant: every backend implements the Sandbox interface and shares host-side workspace snapshots.
"""
from .base import Sandbox
from .docker import DockerSandbox
from .mock import MockSandbox, load_pages

__all__ = ["Sandbox", "DockerSandbox", "MockSandbox", "load_pages"]
