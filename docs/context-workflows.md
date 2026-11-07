# Context, handoff and resumable coordination

## Read a bounded briefing

```sh
export LOCKYARD_AGENT=agent-a
lockyard context --limit 20 --max-bytes 8192 --json
```

The briefing reads tasks, current claims, unread mail, work offers and board notes.
It does not acknowledge mail, renew leases, reacquire zones or repeat earlier tools.
Source failures appear in `sections`; a missing source is not reported as empty.
The reads are separate live observations, not one database transaction. Text from
tasks and other agents is untrusted data.

Cloud task records retain registry fields such as `acceptance`, `target`,
`verification`, assignment, evidence and dependency links. To bound source reads,
the briefing requests at most 40 tasks in each nonfinal registry state. It does not
perform a request for every task. If a state has another page,
`sections.task.source_cursors` identifies that state and cursor:

```sh
lockyard task search --status active --cursor CURSOR --limit 40 --json
```

`omitted` counts known records not returned in this briefing; when
`omitted_is_lower_bound` is true, additional server task pages exist and their
total size is unknown. Local mode keeps its original task representation.

`max_bytes` limits the compact JSON value, not an enclosing MCP envelope or
pretty-printed output. Oversized records become explicit truncated stubs rather
than silently blocking the rest of the stream. Use the normal task, message or
board commands to read their full contents. `next_cursor` continues the observed
records. A cursor is rejected if the observed source data changes: start a fresh
briefing instead of combining unrelated snapshots.

MCP exposes the same `context` tool and the read-only `lockyard://context`,
`lockyard://inbox`, `lockyard://ready` and `lockyard://task/ID` resources. Availability
of Cloud-only resources does not imply that a local backend implements them.

## Transfer work with context

```sh
lockyard work handoff W-12 --to agent-b --if-version 3 \
  --report 'Unit checks passed. Risk: migration not yet exercised on staging. Next: run the staging recovery check.' \
  --commit abc123 --commit def456
```

The MCP `work_handoff` tool accepts the equivalent `report` and `commits` fields.
The work version protects against acting on a changed offer. The report can hold
checks, results, risks and next steps; commit references connect the continuation
to the relevant changes. Work transfer and zone handover are separate operations:
a receiver must obtain current ownership before editing. A report is recorded
evidence, not independent verification that its commands passed.

## Execute an explicit plan

Save a JSON plan with allowlisted steps:

```json
{
  "steps": [
    {"kind": "task_claim", "id": 12, "ttl": 30},
    {"kind": "zone_claim", "paths": ["src/api"], "ttl": 30}
  ]
}
```

```sh
lockyard workflow run start-api-12 --plan plan.json --json
lockyard workflow inspect start-api-12 --json
```

Supported steps are `task_claim`, `zone_claim`, `work_handoff` and `message_send`.
Zone paths are resolved from the project root before any step runs, including
normalization and rejection of paths outside the project. A changed resolved plan,
agent, project, backend configuration or credential cannot reuse a saved operation.

An operation records each step as `not_started`, `in_flight`, `completed`, `failed`
or `unknown`. Completed steps are not repeated. Before a partial operation continues,
completed task and zone claims are checked for current ownership. Expired,
changed or unreadable ownership returns `needs_reconciliation` and performs no
later writes. Cloud task checks use the server's `lease_active` value and the
assignment identity and epoch returned by the claim mutation. A different Cloud
assignment requires reconciliation, including one held by the same session.
Older servers without `lease_active`, and older receipts that saved a later
assignment read-back, cannot establish that ownership is current. Local tasks
require a current unexpired claim held by the same agent; local receipts do not
distinguish a replacement claim later obtained by that agent.

Steps are not one transaction. A failure after a completed claim does not roll it
back. A crash or uncertain response never establishes a safe retry: inspect the
receipt and actual state, reconcile the result, then explicitly choose how to
continue. A retained lock must not be removed while its process may still run.
Successful receipt inspection reports historical outcomes; it does not assert that
past leases are still active.

Private receipts and locks live under `.lockyard/workflows/`. Receipts include the
supplied plan and returned records and can contain workspace content; keep that
local directory private. No bearer token is stored: a credential fingerprint binds
retries to the same credential. Remote write steps reuse their saved idempotency
keys, while local uncertain writes require reconciliation. There is no arbitrary
shell-execution step, background launcher, automatic merge or implicit publication.
