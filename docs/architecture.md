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
- Hands a session's typed output back (change typed-boundaries). A task with `Output` set gets one MCP server,
  `ygg`: Claude Code through `--mcp-config` (with `--strict-mcp-config` kept, so a leaf's `.mcp.json` is never
  read), opencode through the `mcp` key of its configuration (with project configuration switched off). Both start
  exactly `/opt/ygg/bin/ygg-submit` with no arguments and the contract in `YGG_OUTPUT_CONTRACT`. Each adapter
  reads its stream and sets `Result.Submitted` to the output document of the last `submit` call whose tool result
  was `accepted: the document is a valid <contract>`; a call that named a draft file is read through the sandbox
  afterwards (`head -c`, at most 4 MiB, under `out/`), and a draft that cannot be read fails the session as an
  agent failure, with the reason. No accepted call leaves `Submitted` nil. Each adapter implements
  `gungnir.Submitter`; the scripted one by `submits: true` and a step's `submitted`. The `contract` package holds
  the suite every adapter passes. If a CLI cannot run the server, its adapter drops the config and Odin reads the
  strict whole answer.
- Loads skills explicitly per task, from Havamal at a pinned version (spec §5.1).
- Runs commands in sandboxes and applies policies: devcontainer hardening, managed settings and
  the egress firewall (spec §6).
- Starts, beside the work container, the services a leaf's realm and the realms of the leaves it
  consumes ask for (a database, object storage), and opens their ports, and only theirs, to the work
  container through the firewall. The firewall also answers the work container's DNS queries itself, from
  the addresses it allows, so a name served from a large pool never resolves to an address the rules do
  not allow; it resolves nothing but the allowed hosts and the services' names. The services sit on an internal network with no route out, which the
  firewall joins, so none of them can reach the internet for a client. A spec with `Models` names a shared model
  server: the firewall alone joins the server's network (`models`, external), which `Up` refuses unless
  `podman network inspect` says it is internal, and opens the server's name on its one port, as it does a
  service's. Validate refuses any other external or named network. Each sandbox starts on the stack layer its spec names, so leaves of
  different realms differ. A scratch sandbox holds one folder and no git directory: a planner's
  workspace (spec §3.3). A sandbox with no stack (a spec with no `Stack`, as a scratch session's) runs on Gleipnir's
  factory stack, the pinned Node image plus git (`FactoryStack`), under the factory layer: `FactoryImages()`,
  which a caller sets as `Config.Images`. `BuildFactory` builds both, pulling the Node image once.
- Carries `ygg-submit` in the work image: a stdio MCP server (`ygg`, protocol 2025-06-18) through which a session
  hands back its typed output. Its `submit` tool takes the output or a draft file under `out/` and its `check` tool
  takes a draft; both validate against the contract in `$YGG_OUTPUT_CONTRACT` (one of gungnir's `schema.Contracts()`,
  by its exact id; any other is refused) with ajv 8.17.1 and the schemas of gungnir's `schema.SchemaFS()`, answer
  `accepted` or the errors, and write nothing. The managed settings allow
  exactly that one MCP server, by command (`serverCommand: ["/opt/ygg/bin/ygg-submit"]`), because a name would admit any
  command a leaf's `.mcp.json` gave it. An adapter must start exactly `/opt/ygg/bin/ygg-submit` with no arguments and
  pass the contract in `YGG_OUTPUT_CONTRACT`. The ajv tree comes from a lock file (`npm ci`), and the image tag hashes
  the script, the ajv pin, both package files and every schema.
- Tears a sandbox down with `Down`: it removes the containers by label, then the compose pod (`pod_` plus the
  project, which compose leaves behind and `podman pod prune` keeps while it is Created; removed without
  force, and no pod is no error), then the networks. `PodLeftovers` lists the factory's pods that hold no
  container, for `ygg doctor`, and `RemovePod` removes one; `RunPrefix` ties a pod's project to a run id.
- Builds a realm's stack from the realm's build context (`BuildStack`, for `ygg sandbox build`): only
  from images pinned by digest and the Containerfile's own stages, with the isolated registry auth, and
  tagged with a hash of the context. The check scripts a realm bakes into its stack are read-only for the
  agent. A service may take the command its pack gives it, for an image that does nothing without one.
- Builds the model server's image (`BuildModels`, for `ygg models build`; local-models spec §3.4): llama-server
  from llama.cpp at a pinned commit, with CUDA for the architecture given (89 by default), and `ygg-modelgate`, on
  bases pinned by digest in `assets/Containerfile.models`, pulled with the isolated registry auth. `ModelsImage()`
  is its tag, a hash of that file, the entrypoint and the gate's source. The entrypoint starts llama-server on 8080
  and the gate on `YGG_MODELGATE_PORT`, and exits when either exits. The gate (`assets/modelgate`, standard library
  only) is the only path from a sandbox to llama-server: it passes `POST /v1/chat/completions` with no query and a
  JSON body of at most 32 MiB whose one `model` equals the allow file, which it reads on each request, and streams
  the answer. It answers 403 to any other method, path, query or model, 413, 400 or 503 (no allow file).
- Grades a build (`Grade`, spec §11): builds the image of a benchmark task from its `environment/` folder
  (`BuildGrader`, with the rules of `BuildStack`, and a tag that is a hash of the folder), then runs
  `bash /tests/test.sh` in one container of that image, as `bash -c` with a tail that gives `/app` and
  `/logs/verifier` to the container's root (`chown -hR 0:0`, errors ignored) and exits with the suite's own
  status: the suite makes its user own `/app`, which on a rootless engine is a subuid of the host, and the
  host user could not delete the copy afterwards. A container stopped from outside (timeout, cancel, stdout
  bound) cannot run that tail, so `Grade` removes it and then runs a second, short container of the same image
  (`<name>-chown`, `--rm`, no network, the two writable mounts only) that does the chown. The container has no network but loopback and three
  mounts: `/app` (the project, read and write), `/tests` (the suite, read only) and `/logs/verifier` (an empty
  folder for the suite's own logs, which nothing reads as a score). It has the label `ygg.grader=<run id>`,
  and it is always removed, after a pass, a failure, a timeout and a cancel. `Grade` refuses a path it could not mount safely before it runs
  anything, and a `podman run` that exits 125, 126 or 127 is an error, not a result. An empty memory limit and
  zero CPUs mean no limit, for an engine that cannot apply one. `Grade` sets `YGG_SCORE_KEY` (32 hex characters, one per attempt) in
  the container and returns the container's stdout, whole and never mixed with its stderr, up to 32 MiB; over that it kills the process and
  returns an error and no result. `Grade` reads no score: the line the suite prints on stdout is the score, and
  Odin reads it. `GraderLeftovers` finds a container a killed run left, by its label, and `RemoveGrader`
  removes it.
- Runs checks. A check asked for its typed result (`checks.Spec.Typed`, the loop's ladder) gets
  `$YGG_CHECK_RESULT` and has its `ygg.check/v1` read back, guarded and bounded; any other command runs alone, with no
  environment of its own. `ygg-check-result`, in the work image, writes that result from a tool's machine output and
  keeps it under 768 KiB.

## Depends on

- Gungnir.
- Podman and the devcontainer CLI on the host.

## Source

The v0 engineering spec, §2.1, §5, §6. When this page and the spec differ, the spec wins.
