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
- The `opencode` adapter names a reasoning effort on every request of a role: `Config.Reasoning` is `low`,
  `medium` or `high`, and unset means `high`. `off` names none, so the model runs on its own default effort;
  deepseek-v4-flash took its prompt for an empty message in that state (v0-H17). Another value is an error from
  `New` and `ConfigJSON`. The `claude-code` and `scripted` adapters ignore the setting. Whether OpenRouter rejects
  `low` or `medium` for a model that does not support them is unverified.
- Loads skills explicitly per task, from Havamal at a pinned version (spec §5.1).
- Runs commands in sandboxes and applies policies: devcontainer hardening, managed settings and
  the egress firewall (spec §6).
- Starts, beside the work container, the services a leaf's realm and the realms of the leaves it
  consumes ask for (a database, object storage), and opens their ports, and only theirs, to the work
  container through the firewall. The firewall also answers the work container's DNS queries itself, from
  the addresses it allows, so a name served from a large pool never resolves to an address the rules do
  not allow; it resolves nothing but the allowed hosts and the services' names. The services sit on an internal network with no route out, which the
  firewall joins, so none of them can reach the internet for a client. Each sandbox starts on the stack layer its spec names, so leaves of
  different realms differ. A scratch sandbox holds one folder and no git directory: a planner's
  workspace (spec §3.3). A sandbox with no stack (a spec with no `Stack`, as a scratch session's) runs on Gleipnir's
  factory stack, the pinned Node image plus git (`FactoryStack`), under the factory layer: `FactoryImages()`,
  which a caller sets as `Config.Images`. `BuildFactory` builds both, pulling the Node image once.
- Builds a realm's stack from the realm's build context (`BuildStack`, for `ygg sandbox build`): only
  from images pinned by digest and the Containerfile's own stages, with the isolated registry auth, and
  tagged with a hash of the context. The check scripts a realm bakes into its stack are read-only for the
  agent. A service may take the command its pack gives it, for an image that does nothing without one.
- Grades a build (`Grade`, spec §11): builds the image of a benchmark task from its `environment/` folder
  (`BuildGrader`, with the rules of `BuildStack`, and a tag that is a hash of the folder), then runs
  `bash /tests/test.sh` in one container of that image. The container has no network but loopback and three
  mounts: `/app` (the project, read and write), `/tests` (the suite, read only) and `/logs/verifier` (an empty
  folder for the results). It has the label `ygg.grader=<run id>`, and it is always removed, after a pass, a
  failure, a timeout and a cancel. `Grade` refuses a path it could not mount safely before it runs
  anything, and a `podman run` that exits 125, 126 or 127 is an error, not a result. An empty memory limit and
  zero CPUs mean no limit, for an engine that cannot apply one. `Grade` reads no result: the score is
  Odin's. `GraderLeftovers` finds a container a killed run left, by its label, and `RemoveGrader` removes it.
- Runs checks.

## Depends on

- Gungnir.
- Podman and the devcontainer CLI on the host.

## Source

The v0 engineering spec, §2.1, §5, §6. When this page and the spec differ, the spec wins.
