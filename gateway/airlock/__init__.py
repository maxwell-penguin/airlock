"""Airlock gateway: the trusted layer between an AI agent and everything else.
Role: package root. Layers: all (see docs/ARCHITECTURE.md).
Invariant: the agent and sandbox are untrusted; every action enters via Gateway.submit().
"""
