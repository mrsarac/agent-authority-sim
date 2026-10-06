# Authority and Promotion State Machines

Schema version: `0.1.0`
Status: validated normative design; simulator not implemented

## 1. Purpose

Define deterministic, model-free state transitions for authority, capabilities, runs, receipts, and promotion. Every accepted transition is append-only, idempotent, and bound to an expected prior state.

No automatic failover, remote node, real key, wall-clock service, or production database is part of this model.

## 2. Authority tuple

The canonical authority tuple is:

```text
(operator_id,
 authority_epoch,
 lease_generation,
 writer_id,
 lease_id,
 expires_at,
 policy_digest,
 authority_head_digest)
```

Rules:

1. `authority_epoch` increases only through initialization or Operator-authorized recovery/takeover.
2. `lease_generation` increases when a writer lease is replaced or reissued inside the same epoch.
3. Renewal of the same valid writer-instance lease extends `expires_at` without changing generation.
4. Promotion requires the exact current epoch and lease generation.
5. The authority core's clock is authoritative for lease validation. Worker timestamps are evidence only. Accepted authority-event `observed_at` values MUST be monotonically non-decreasing; a backward clock contradiction freezes promotion in `RECOVERY_REQUIRED`.
6. A higher epoch fences every lower epoch permanently.
7. A higher lease generation fences every lower generation in the same epoch.
8. No model, worker, adapter, or surface may issue or renew this tuple.

Every acquisition, renewal, reissue, and recovery MUST create an immutable `authority_lease` record. Renewal preserves stable lease ID and generation but creates a new lease-record ID; reissue changes stable lease ID and increments generation; recovery/takeover increments epoch. The accepted authority event references that record's digest.

Renewal is a heartbeat extension of the same writer instance and logical lease term. Any writer-instance or stable-lease-ID change is a reissue and increments generation. This distinction prevents both stale-term acceptance and needless fencing of long-running tasks at every heartbeat.

Expiry is evaluated from the latest accepted lease record at an explicit authority `as_of` time. At `as_of >= expires_at`, authority derives `NO_WRITER`; there is no implicit grace interval. Heartbeat scheduling is operational guidance, not authority state, and cannot extend validity without an accepted immutable renewal record. Expiry is not an event an already expired writer may append.

## 3. Authority-writer states

States:

- `UNINITIALIZED`
- `NO_WRITER`
- `ACTIVE`
- `FENCED`
- `RECOVERY_REQUIRED`
- `HALTED`

### Transition table

| Current | Event | Preconditions | Next | Canonical effect |
|---|---|---|---|---|
| `UNINITIALIZED` | `authority_initialized` | Operator bootstrap approval; verified empty log | `ACTIVE` | epoch `1`, generation `1`, first writer lease |
| `ACTIVE` | `lease_renewed` | same writer, epoch, generation, lease ID; unexpired; policy unchanged | `ACTIVE` | extend expiry; append one event |
| `ACTIVE` | `lease_released` | current writer instance or Operator authorizes a final compare-and-append | `NO_WRITER` | graceful relinquishment; promotion pauses |
| `ACTIVE` | authority clock observes lease expiry | explicit authority `as_of >= expires_at` | `NO_WRITER` | derived state; promotion pauses; expired writer appends nothing |
| `ACTIVE` | `authority_fenced` | verified higher epoch or Operator recovery begins | `FENCED` | reject all further writes from old tuple |
| `NO_WRITER` | `lease_acquired` | Operator-authorized recovery; verified log and revocations | `ACTIVE` | higher epoch; generation `1` |
| `FENCED` | any ordinary write | none | `FENCED` | reject `AUTHORITY_STALE`; no append by fenced writer |
| any non-halted state | chain, restore, writer, policy, or clock contradiction | deterministic verifier cannot establish one valid head | `RECOVERY_REQUIRED` | freeze promotion |
| `RECOVERY_REQUIRED` | `restore_verified` | Operator approval; complete chain/revocation/policy verification | `ACTIVE` | higher recovery epoch; append recovery event |
| any state | `authority_halted` | Operator emergency stop | `HALTED` | task issuance and promotion stop |
| `HALTED` | `restore_verified` | two-step Operator recovery; complete verification | `ACTIVE` | higher recovery epoch |

`NO_WRITER`, `FENCED`, `RECOVERY_REQUIRED`, and `HALTED` MUST reject canonical promotion.

A surface MAY queue intent while no writer exists. A worker MAY finish already-issued local work while its task and capability remain unexpired. Those results remain proposals and cannot promote until a valid writer evaluates them; any epoch change makes the old result stale for promotion.

## 4. Task states

States:

- `ISSUED`
- `ACTIVE`
- `EVIDENCE_PENDING`
- `PROMOTION_PENDING`
- `PROMOTED`
- `COMPLETED_NO_CHANGE`
- `REJECTED`
- `QUARANTINED`
- `REVOKED`
- `EXPIRED`

| Current | Event | Preconditions | Next | Effect |
|---|---|---|---|---|
| none | `task_issued` | current authority tuple; valid decision reference, policy, capability plan, budget, and expected head | `ISSUED` | immutable envelope appended |
| `ISSUED` | first run claimed | valid task and capability; authority time before task expiry | `ACTIVE` | run linked to task |
| `ACTIVE` | terminal run submits receipt | receipt schema accepted | `EVIDENCE_PENDING` | no promotion |
| `EVIDENCE_PENDING` | receipt verified | task/capability/epoch/policy/evidence bindings pass | `PROMOTION_PENDING` | proposal may be evaluated |
| `EVIDENCE_PENDING` | receipt rejected | retry policy and capability remain valid | `ACTIVE` | a new run ID may be issued; constraints cannot weaken |
| `EVIDENCE_PENDING` | receipt rejected | retry unavailable or exhausted | `REJECTED` | terminal task failure |
| `PROMOTION_PENDING` | promotion recorded with accepted artifacts | active authority and compare-and-append pass | `PROMOTED` | exactly one promotion effect |
| `PROMOTION_PENDING` | promotion recorded as `record_no_change` | acceptance checks pass | `COMPLETED_NO_CHANGE` | terminal success without artifact mutation |
| `PROMOTION_PENDING` | proposal rejected | deterministic rejection | `REJECTED` | canonical project/artifact state unchanged |
| any non-terminal state | evidence contradiction | deterministic verification cannot resolve one valid state | `QUARANTINED` | promotion pauses |
| any non-terminal state | `task_revoked` | current authority writer | `REVOKED` | all task capabilities deny new work and promotion |
| any non-terminal state | authority clock passes task expiry | explicit authority `as_of` time | `EXPIRED` | derived terminal state; no synthetic expiry event required |
| terminal state | replay or new run/proposal | none | same terminal state | idempotent read-back or deny |

A task may have several failed run attempts only while retry policy, capability, epoch, policy, budget, and expiry remain valid. It has at most one accepted promotion effect.

`task_issued` and its initial `capability_issued` MUST be committed as one atomic compare-and-append batch. A crash may leave neither event, never only one. Restore that observes an orphaned task/capability pair MUST enter `RECOVERY_REQUIRED`.

## 5. Capability states

States:

- `ISSUED`
- `ACTIVE`
- `EXPIRED`
- `REVOKED`
- `CONSUMED`

| Current | Event | Preconditions | Next | Effect |
|---|---|---|---|---|
| none | `capability_issued` | current authority tuple; valid task and parent attenuation | `ISSUED` | immutable claim appended |
| `ISSUED` | first valid use | valid time, audience, task, policy, epoch/generation | `ACTIVE` | use recorded |
| `ISSUED` or `ACTIVE` | authority time passes expiry | none | `EXPIRED` | deny new work and promotion |
| `ISSUED` or `ACTIVE` | `capability_revoked` | current authority writer | `REVOKED` | deny new work and promotion immediately |
| `ACTIVE` | single-use task consumed | terminal run receipt accepted | `CONSUMED` | deny another run unless task explicitly allows retries |
| terminal state | any use/reissue attempt | none | same terminal state | deny; no resurrection |

Revocation and expiry are monotonic. Reissuing equivalent rights requires a new capability ID, revocation ID, nonce, and current authority binding.

## 6. Run states

Run state is governor/runtime evidence only. It is intentionally not an `authority_event` state-machine domain and does not create canonical events for `run_created`, `run_claimed`, or `run_started`. Its terminal outcome enters canonical evaluation only through an execution receipt.

States:

- `CREATED`
- `CLAIMED`
- `RUNNING`
- `SUCCEEDED`
- `FAILED`
- `CANCELLED`
- `TIMED_OUT`
- `DENIED`

| Current | Event | Preconditions | Next |
|---|---|---|---|
| none | `run_created` | valid task and capability | `CREATED` |
| `CREATED` | `run_claimed` | exact subject/audience; replay nonce unused | `CLAIMED` |
| `CLAIMED` | `run_started` | budget and policy observer active | `RUNNING` |
| `RUNNING` | process exits `0`; no hard bound violated | governor observation | `SUCCEEDED` |
| `RUNNING` | process exits nonzero | governor observation | `FAILED` |
| `CREATED`, `CLAIMED`, or `RUNNING` | cancellation accepted | governor observation | `CANCELLED` |
| `RUNNING` | authority/governor deadline reached | governor observation | `TIMED_OUT` |
| `CREATED` or `CLAIMED` | identity, scope, policy, revocation, or adapter check fails | fail closed | `DENIED` |
| terminal state | any transition | none | same terminal state; reject relabeling |

A timeout or cancellation can retain partial artifacts as quarantined evidence. It cannot produce a success receipt.

## 7. Receipt states

States:

- `SUBMITTED`
- `VERIFIED`
- `REJECTED`
- `QUARANTINED`

| Current | Event | Preconditions | Next |
|---|---|---|---|
| none | receipt submitted | strict schema parse | `SUBMITTED` |
| `SUBMITTED` | receipt accepted | identity, authority, capability, process, bounds, artifact, and trust checks pass | `VERIFIED` |
| `SUBMITTED` | deterministic validation fails | generic closed reason code | `REJECTED` |
| `SUBMITTED` | contradictory or insufficient evidence needs recovery/manual inspection | no canonical mutation | `QUARANTINED` |
| terminal state | same receipt replayed | same idempotency key and bytes | same terminal state |
| terminal state | same ID with different submitted bytes | untrusted duplicate/conflict | same terminal state | reject or quarantine `REPLAY_DETECTED`; authority remains active |

A conflicting untrusted submission cannot force global recovery. `RECOVERY_REQUIRED` is reserved for a mismatch in bytes already accepted into canonical storage or for contradictory accepted authority events.

Receipt verification does not promote artifacts. It establishes only that the recorded evidence meets the declared receipt contract.

## 8. Promotion states

States:

- `NONE`
- `PROPOSAL_RECEIVED`
- `RECEIPT_VERIFIED`
- `PROMOTED`
- `REJECTED`
- `QUARANTINED`

| Current | Event | Preconditions | Next | Canonical mutation |
|---|---|---|---|---|
| `NONE` | proposal submitted | strict schema; valid task reference | `PROPOSAL_RECEIVED` | no project/artifact mutation |
| `PROPOSAL_RECEIVED` | receipts verified | every required receipt/evidence check passes | `RECEIPT_VERIFIED` | verification event only |
| `PROPOSAL_RECEIVED` or `RECEIPT_VERIFIED` | validation rejection | closed reason code | `REJECTED` | rejection event only |
| either pending state | contradiction/uncertain restore state | recovery/manual inspection required | `QUARANTINED` | no promotion |
| `RECEIPT_VERIFIED` | promotion decision | active authority tuple; expected head; idempotency; acceptance checks | `PROMOTED` | one atomic promotion event |
| terminal state | replay | same bytes and idempotency key | same result; no new promotion event |
| terminal state | alternate result for same proposal/task | none | reject `REPLAY_DETECTED` or enter recovery on digest contradiction |

A task can have many failed/rejected run attempts, but at most one accepted promotion effect per task idempotency domain.

## 9. Policy states

States:

- `UNINITIALIZED`
- `ACTIVE`
- `RECOVERY_REQUIRED`

| Current | Event | Preconditions | Next | Effect |
|---|---|---|---|---|
| `UNINITIALIZED` | `policy_activated` | Operator authorization; expected head; valid non-rollback floor | `ACTIVE` | first approved policy digest |
| `ACTIVE` | `policy_activated` | strictly allowed policy evolution; expected head | `ACTIVE` | append new approved policy digest |
| `ACTIVE` | downgrade/unknown activation attempt | monotonic policy floor fails | `ACTIVE` | reject; no append |
| any state | accepted canonical policy bytes conflict on restore | one valid policy cannot be established | `RECOVERY_REQUIRED` | freeze promotion |
| `RECOVERY_REQUIRED` | `policy_recovery` | Operator approval; higher recovery epoch; non-rollback floor verified | `ACTIVE` | append recovery policy event |

## 10. Promotion validation algorithm

The authority writer MUST execute these checks in order:

1. Strictly parse document kind and schema version.
2. Reject unknown fields and malformed types.
3. Match operator, task, proposal, receipt, capability, artifact, node, process, and adapter identities.
4. Compare exact current epoch and lease generation.
5. Verify writer lease using authority-core time.
6. Match active policy digest and reject unauthorized rollback.
7. Verify task expiry, capability validity, audience, revocation, and attenuation.
8. Verify required adapter features; unknown or missing means deny.
9. Verify run terminal state and externally observed process result.
10. Verify hard resource ceilings.
11. Verify observation trust class per acceptance check.
12. Recompute manifest digest and verify every artifact ID/content-digest/manifest-digest pin against immutable bytes.
13. Compare `expected_authority_head` with current head.
14. Check task, receipt, proposal, and idempotency replay sets.
15. Execute acceptance-specific validators.
16. Build one promotion decision and one authority event.
17. Atomically compare-and-append against the expected head.
18. Return the resulting head and projection status.

Any failure before step 16 produces no promotion event. A race at step 17 rejects the candidate with `EXPECTED_HEAD_MISMATCH`; it is re-evaluated from current state rather than blindly retried.

## 11. Event-chain profile for simulation

The simulator uses a deterministic simulation profile, not a production signing format.

`canonical-json-v0.1` canonical bytes:

1. UTF-8;
2. recursively sorted object keys;
3. no insignificant whitespace;
4. JSON separators `,` and `:`;
5. integers only for numeric fields; floats and non-finite values forbidden;
6. Unicode preserved without implementation-specific escaping differences;
7. `event_digest` omitted while calculating the event digest.

```text
event_digest = "sha256:" + SHA256(canonical_event_body_without_event_digest)
```

`previous_event_digest` MUST equal the preceding accepted event's `event_digest`; genesis uses `null`. The canonical authority head is the last accepted digest.

Accepted `observed_at` values MUST be monotonically non-decreasing by sequence. Worker clocks never determine this ordering.

A canonical object referenced by an event MUST NOT embed that future event's ID or digest. In particular, a promotion decision contains the prior head only; the event references the decision digest, and the append result returns the new event ID/head separately. This keeps hashing acyclic.

A production encoding/signature profile is deferred.

`policy_evidence` and `restore_evidence` object kinds are opaque content-addressed evidence in schema `0.1.0`, not top-level contract documents. Their event records bind exact object digests and closed transitions; the evidence bytes cannot mutate state independently. Internal evidence serialization remains deferred rather than silently becoming a decision-plane/runtime protocol.

## 12. Restore algorithm

Restore output is deterministic for the tuple `(approved checkpoint, exact event and referenced canonical-object bytes, explicit authority as_of time)`. The implementation MUST NOT read ambient wall time during reconstruction.

1. Start from an approved empty genesis or approved checkpoint.
2. Parse every event and every referenced contract object using its declared schema version.
3. Resolve every event object reference and recompute its object digest from exact bytes; opaque policy/restore evidence is digest-verified but not semantically parsed in `0.1.0`.
4. Recompute each event digest from canonical bytes.
5. Verify sequence monotonicity and previous-digest continuity.
6. Rebuild policy, epoch, lease, task, capability, revocation, receipt, promotion, and idempotency projections.
7. Verify no transition violates its expected prior state.
8. Verify the reconstructed head equals the checkpoint head.
9. Compare restored epoch and policy against the non-rollback floor.
10. If all checks pass, append `restore_verified` in a higher recovery epoch.
11. On any missing object, digest mismatch, or transition contradiction, append nothing and enter `RECOVERY_REQUIRED` using a separate trusted recovery record.

Provider conversations, caches, live worker state, and UI projections are never restore dependencies.

## 13. Idempotency rules

- Replaying byte-identical input with the same object ID, idempotency key, and—where the contract carries one—nonce returns the original result without a new semantic effect.
- For contracts that carry a nonce, it may be reused only for that byte-identical replay. Reusing it with another object ID or different bytes is rejected as `REPLAY_DETECTED`.
- Reusing an ID or idempotency key with different submitted bytes is rejected or quarantined as an untrusted contradiction, not treated as an update. Global recovery begins only if already accepted canonical bytes or authority events conflict.
- A promoted task cannot be promoted again through a new receipt or proposal.
- A rejected proposal can be replaced only by a new proposal ID that references new evidence and the current authority head.
- Retries never weaken original task, capability, policy, budget, or acceptance constraints.

## 14. Cross-state invariants

1. Worker and adapter state cannot invoke authority append.
2. Promotion requires `ACTIVE` authority, non-terminal valid capability, terminal successful run, verified receipt, and current expected head.
3. Revoked, expired, fenced, cancelled, timed-out, denied, rejected, or quarantined state cannot be promoted.
4. Any higher authority epoch invalidates lower-epoch promotion attempts.
5. Any higher lease generation invalidates lower-generation attempts in the same epoch.
6. Every projection is rebuildable from accepted authority events, referenced canonical-object bytes, and pinned artifact manifests.
7. A conflicting untrusted submission is rejected/quarantined without changing authority state; a digest contradiction in already accepted canonical bytes enters `RECOVERY_REQUIRED`.
8. Promotion binds exact artifact ID, content digest, and manifest digest; bare artifact IDs cannot promote.
9. Task and initial capability issuance are atomic; orphaned accepted state is a recovery condition.
10. No transition reads model prose as authority evidence.
