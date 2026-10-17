---
title: Gleipnir architecture
status: draft
date: 2026-10-12
related: [https://github.com/ouroboric-dev/yggdrasil/blob/main/docs/2-engineering/specs/2026-10-11-yggdrasil-v0-spec.md]
style: reference
---

# Gleipnir architecture

The harness: agent adapters, the devcontainer sandbox driver, policies and the check runner.

## Responsibilities

- Turns a task into an agent session: assembles context, calls the adapter (`claude-code`,
  `opencode` or `scripted`) and captures usage.
- Loads skills explicitly per task, from Havamal at a pinned version (spec §5.1).
- Runs commands in sandboxes and applies policies: devcontainer hardening, managed settings and
  the egress firewall (spec §6).
- Starts, beside the work container, the services a leaf's realm and the realms of the leaves it
  consumes ask for (a database, object storage), and opens their ports, and only theirs, to the work
  container through the firewall. Each sandbox starts on the stack layer its spec names, so leaves of
  different realms differ. A scratch sandbox holds one folder and no git directory: a planner's
  workspace (spec §3.3).
- Runs checks.

## Depends on

- Gungnir.
- Podman and the devcontainer CLI on the host.

## Source

The v0 engineering spec, §2.1, §5, §6. When this page and the spec differ, the spec wins.
