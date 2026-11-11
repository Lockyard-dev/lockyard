<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->

# Cloud zone mirror — local-fast hook guarantee

## Goal

A Claude Code (or other) edit hook must answer in milliseconds. Talking to the cloud server on every
`PreToolUse` is too slow (field runs saw ~1 s). The background agent therefore keeps a **local
mirror** of the workspace's zone claims, fed by the server event stream (long-poll
`GET /api/v1/events`), and the hook asks that mirror over a Unix socket.

## Guarantee

1. **Fresh view → answer from memory.** While the view's generation matches the last absorbed event
   generation and both the monotonic and wall clocks say the view is younger than `Timing::fresh`
   (default **30 seconds**), a path check is answered from the in-process claim list. No HTTP. The
   measured p95 on a quiet machine is under 5 ms (unit test
   `a_fresh_view_answers_from_memory_in_under_5_ms_with_no_server_call`); the CI budget is p95 ≤ 15 ms
   for the local hook path.
2. **Stale view → fail closed.** If the view is older than `Timing::fresh`, or an event arrived that
   the snapshot has not absorbed, the hook does **not** treat the path as free. The agent may make
   one short server call (deadline 800 ms); if that also fails, the check is `Unknown` and the hook
   **denies** the edit. A laptop that slept with a frozen mirror cannot allow a write the server
   would refuse.
3. **No agent process → deny edits.** Cloud mode without `lockyard agent` has no mirror; PreToolUse
   edit tools are refused with a message to start the agent.
4. **Leases are server time.** The mirror never compares a claim's `expires_at` to the client's
   clock. A claim leaves the view only when the server says so (release, expiry event, refresh).
   The 30-second freshness bound is the fence on the *mirror*, not a second lease.

## Events and reconcile

The agent long-polls the coordination event stream and invalidates the view on zone events, then
refreshes claims from the server. A periodic upkeep pass also refreshes so a missed event costs
latency, not a permanent lie. The same "events accelerate, reconcile is truth" rule applies to the
filesystem monitor on disk.

The lost list may contain `idle`, `expired`, or `unused_grant` entries as well as takeover losses.
An idle shrink can release only clean paths while retaining the claim's dirty paths. The agent
keeps lost history separate from live claims; check, activity, and release decisions use the live
claims. A historical lost entry for the same id cannot invalidate the claim's remaining paths.

## What this is not

The mirror is not authoritative for mutations. Every claim, renew, release and mail send still goes
to the server with an idempotency key. The mirror exists only so **reads that gate an edit** stay
local-fast without going open when wrong.
