# Fake-Worker Property-Test Catalog

Schema version: `0.1.0`
Status: validated simulator test design only; no simulator code exists

## 1. Proof goal

Use a deterministic, model-free fake-worker system to falsify the authority contract before any real CLI, node, key, network, service, or secret is involved.

The simulator is not a security product. It proves only that the documented semantics can be represented and that named failure cases are rejected in the finite model.

## 2. Logical simulator components

The future implementation will need these isolated units:

| Component | Responsibility | Forbidden responsibility |
|---|---|---|
| `FakeClock` | deterministic authority and worker times; controlled skew | reading real wall time |
| `InMemoryAuthorityLog` | compare-and-append events; replay and chain checks | accepting worker writes |
| `AuthorityCore` | current tuple, task issue, verification, promotion, recovery | model reasoning or secret storage |
| `CapabilityBroker` | issue, attenuate, expire, and revoke semantic claims | self-blessing caller claims |
| `PolicyStub` | closed deterministic policy decisions and obligations | natural-language policy interpretation |
| `ArtifactStore` | immutable bytes and manifest/digest verification | semantic correctness claims |
| `FakeAdapter` | capability declaration and structured event translation | hiding unknown features |
| `FakeWorker` | execute scripted outcomes and submit evidence proposals | canonical append or promotion |
| `ReceiptVerifier` | trust-class, process, budget, artifact, and identity checks | accepting model assertion alone |
| `ProjectionBuilder` | rebuild read models from accepted events | holding unrecoverable canonical state |

Every component must be independently testable and deeply immutable at public boundaries.

## 3. Simulation constraints

- No network implementation or import.
- No subprocess or real CLI invocation.
- No environment, keychain, credential file, or home-directory access.
- No absolute private paths in fixtures.
- No raw prompts, transcripts, or message content.
- Synthetic operator, node, adapter, task, artifact, and receipt identities only.
- All times come from `FakeClock`.
- All random sequences use an explicit seed and print the seed on failure.
- Canonical serialization contains no floats.
- Test fixtures never mutate production policy or contract files.
- Secret-scanner tests construct token-shaped synthetic strings at runtime from non-sensitive fragments rather than storing a literal signature in source.

## 4. Core model state

The finite model contains:

```text
authority tuple and immutable authority lease records
accepted authority events
active policy digest and non-rollback floor
tasks by ID
capabilities and revocations by ID
runs by ID
artifacts by ID and content digest
receipts by ID and verification state
promotion proposals and decisions by ID
idempotency keys and canonical input digests
```

Provider sessions, chat history, prompt cache, and model memory are deliberately absent.

## 5. Required research invariants

### P01 — Single writer per epoch

**Given:** active writer A and disconnected writer B share epoch `n` before partition.

**When:** Operator recovery creates epoch `n+1` for B and both attempt promotion.

**Then:** only B at `n+1` can append; A is fenced; accepted promotion effects for the task are at most one.

### P02 — Stale or expired authority cannot promote

Generate lower epoch, lower lease generation, expired lease, and mismatched writer cases independently. Every case must fail with a closed authority reason and leave the head unchanged.

Generate lease records/events for acquire, renew, release, reissue, and recovery. Verify:

- renewal uses a new lease-record ID but preserves stable lease ID, writer, epoch, and generation;
- reissue uses a new stable lease ID and higher generation;
- recovery/takeover uses a higher epoch;
- issue time is not after validity start, and validity start is before expiry;
- previous lease-record linkage and expected authority state match current canonical state;
- expiry is derived from explicit authority `as_of` time and cannot be appended by the expired writer.
- graceful release moves `ACTIVE` to `NO_WRITER`, and a later acquisition uses a higher epoch.

### P03 — Capability attenuation

For every parent/child pair:

```text
child.actions ⊆ parent.actions
child.artifacts ⊆ parent.artifacts
child.egress ⊆ parent.egress
child.broker_handles ⊆ parent.broker_handles
child.validity ⊆ parent.validity
child.resource_bound[k] <= parent.resource_bound[k]
child.workspace == parent.workspace
child.operator/task/epoch/policy == parent binding
child.delegation_depth > parent.delegation_depth
```

Omit each condition independently and verify denial.

### P04 — Revocation is monotonic

After revocation, attempt new claim, run start, receipt verification, promotion, reconnect, clock rollback, and replay. Every path must deny. No ordinary event can return a revoked capability to active.

### P05 — Promotion idempotency

Replay the same task, receipt, proposal, and decision individually and in permutations. Byte-identical replay with the same ID, idempotency key, and—where present—nonce returns the prior result without a new semantic event. Reusing a nonce for another object or different bytes is rejected. Same ID/key with different submitted bytes is rejected or quarantined without changing authority state; only a contradiction in already accepted canonical bytes enters recovery. Promotion effect count remains one.

### P06 — Worker cannot append authority events

Expose every public worker, adapter, and receipt interface. Assert there is no append, promote, policy update, lease renew, epoch increment, or recovery method. Attempt crafted `authority_event` submission through all worker paths; deny without state change.

### P07 — Policy rollback requires Operator recovery

Activate policy versions monotonically. Attempt lower-version/digest activation by worker, coordinator, ordinary authority method, restore, and replay. Only an Operator-authorized recovery event in a higher epoch may cross the non-rollback floor.

### P08 — Artifact hash and acceptance evidence

Test:

- correct bytes and manifest;
- wrong bytes with claimed digest;
- same artifact ID with substituted bytes or manifest;
- correct content digest with wrong manifest digest;
- bare artifact ID without content/manifest pin;
- correct bytes but wrong length;
- correct hash but failed semantic acceptance check;
- missing required evidence;
- lower-than-required trust class;
- artifact from another task/operator.

Only the fully matching case may reach promotion.

### P09 — No secret material in serializable contracts

For every document kind:

- insert unknown secret-shaped keys at every object depth;
- replace opaque broker handle with raw synthetic value;
- insert environment, prompt, transcript, message, credential, private-key, cookie, or authorization fields;
- attempt secret-shaped content inside forbidden extension objects.

Strict schema validation must reject the document. The model-visible task projection must not contain governor-only capability or broker handles.

This proves structural exclusion, not perfect secret detection inside arbitrary human text. A separate scanner remains necessary at artifact/context boundaries.

### P10 — Unknown adapter capabilities fail closed

Generate missing, blank, unknown, case-variant, stale-version, and manifest-drift feature declarations. If a task requires a feature not exactly declared by the pinned adapter identity, routing and run start must deny.

### P11 — Cancellation and timeout are terminal

For each non-terminal run state, apply cancellation and applicable timeout. Verify terminal state, no success relabel, partial artifacts quarantined, and promotion denied. Replay cannot change the outcome.

### P12 — Restore preserves canonical semantics

For an accepted event chain and its referenced canonical objects:

- restore exact bytes and compare all projection bytes;
- delete, duplicate, reorder, or alter each event position;
- truncate tail;
- roll back policy, epoch, lease generation, revocation, or idempotency state;
- change schema version without a migration.
- replace artifact or manifest bytes while preserving the artifact ID.

Exact restore must reproduce the head and projections. Every mutation must enter `RECOVERY_REQUIRED` with no promotion.

## 6. Additional threat properties

### P13 — Expected-head race

Two valid proposals share one expected head. Randomize evaluation order. Exactly one compare-and-append succeeds; the other gets `EXPECTED_HEAD_MISMATCH` and is not blindly retried.

### P14 — Path escape

Generate absolute paths, home shortcuts, parent traversal, symlink-like aliases, and workspace-ref mismatches. Contracts must reject raw paths; the future workspace resolver must reject any resolution outside the synthetic root.

### P15 — Budget breach

Independently exceed wall time, tool calls, output bytes, fresh input tokens, output tokens, network requests, and process count. Each breach must deny or terminate according to policy; no urgent/special branch may bypass a hard cap.

### P16 — Network deny by default

With zero egress aliases and zero network-request budget, every attempted destination denies. With one logical allowlist alias, only its exact resolved synthetic destination is eligible. Redirect and DNS behavior are out of scope until a real network adapter phase.

### P17 — Cross-operator and cross-task confusion

Permute operator, task, capability, artifact, receipt, proposal, workspace, and policy references. Any cross-domain reference must deny before acceptance checks.

### P18 — Clock skew

Move worker time forward and backward around task/capability expiry. Authority decisions must depend on `FakeClock` authority time, not worker timestamps. Worker time remains evidence metadata.

### P19 — Receipt trust downgrade

For every acceptance check, substitute each lower trust class and `unknown`. A weaker class cannot satisfy a stronger requirement. `model_asserted` alone never promotes.

### P20 — Provider/session/cache irrelevance

Add, remove, and permute arbitrary synthetic provider-session and cache metadata outside canonical state. Authority events, task bytes, and projection bytes must remain identical.

### P21 — Idle fleet token/context invariance

For one fixed task and relevant state, register `0`, `1`, `10`, and `100` idle synthetic nodes/adapters. Serialized task-envelope bytes must remain identical. The serializer must not enumerate idle fleet state.

### P22 — Malformed API boundary

Send nulls, wrong types, booleans-as-integers, blank/padded IDs, duplicate list entries, mappings/strings where iterables are expected, invalid dates, and hostile iterable/timezone objects at public constructors. Return generic denied validation; do not crash or echo supplied values.

### P23 — Authority event domain binding

For every authority event type, permute all object kinds and state-machine domains. Only the declared type→object-kind→state-domain mapping may validate. Generate invented state names and out-of-domain states; strict schema validation must reject them.

### P24 — Atomic task and initial capability issuance

Inject a crash before, between, and after the two sequential event bytes in the compare-and-append batch. Before/between leaves neither event accepted; after leaves both. Restore that is manually seeded with only one accepted half must enter `RECOVERY_REQUIRED`.

### P25 — Receipt terminal-state coherence

Generate `failed` receipts with every combination of exit code, signal, budget breach, and observation status. `failed` requires at least one concrete failure signal. `success` requires exit zero, no signal, and no budget breach; acceptance checks still decide whether the artifact may promote.

### P26 — Authority clock monotonicity and graceful release

Move worker clocks arbitrarily; authority outcome must not change. For the latest accepted lease, verify `as_of < expires_at` remains eligible and `as_of >= expires_at` derives `NO_WRITER` with no grace interval. Vary operational heartbeat scheduling without accepting a renewal record and assert authority outcome does not change. Attempt an authority event whose `observed_at` is earlier than the accepted predecessor; promotion freezes in `RECOVERY_REQUIRED`. A valid `lease_released` event moves `ACTIVE` to `NO_WRITER`; no promotion occurs until Operator-authorized higher-epoch acquisition.

## 7. Exhaustive transition matrices

The implementation must materialize and assert the complete matrix for:

1. every authority state × authority event;
2. every task state × task/run/receipt/promotion/revoke/expiry event;
3. every capability state × use/revoke/expire event;
4. every run state × run outcome;
5. every receipt state × validation result;
6. every promotion state × proposal/verification/decision/replay event;
7. every policy state × activation/rollback/recovery event;
8. every authority event type × object kind × state-machine domain.

Unexpected combinations deny. Terminal states remain terminal. Matrix size and covered pairs must be computed by the test, not claimed in prose.

## 8. TDD execution order

No production simulator code may be written before the corresponding RED test is observed.

Vertical slices:

1. strict valid/invalid contract parse;
2. one valid authority initialization and task issue;
3. one valid fake run and receipt verification;
4. one valid promotion compare-and-append;
5. worker direct-append denial;
6. stale epoch and expected-head race;
7. attenuation and revocation;
8. replay and conflicting-ID handling;
9. cancellation, timeout, and budget enforcement;
10. artifact/trust/acceptance verification;
11. restore and hash-chain reconstruction;
12. fleet/context invariance;
13. event-domain, receipt-coherence, and atomic-issuance regression cases;
14. full transition matrices and mutation checks.

For each slice:

1. write one behavior test;
2. run it and verify failure for the intended missing behavior;
3. write the smallest implementation;
4. run the focused test;
5. run the complete suite;
6. refactor only while green.

## 9. False-green defenses

The suite must prove its own sensitivity:

- Disable epoch comparison and verify P01/P02 turn red.
- Change attenuation subset comparison to unconditional allow and verify P03 turns red.
- Ignore revocation and verify P04 turns red.
- remove the idempotency check and verify P05/P13 turn red.
- permit worker append and verify P06 turns red.
- skip artifact/content/manifest pin verification and verify P08 turns red.
- accept unknown adapter features and verify P10 turns red.
- relabel timeout as success and verify P11 turns red.
- skip one chain link and verify P12 turns red.
- enumerate idle nodes into task context and verify P21 turns red.
- disable event type/object/state-domain mapping and verify P23 turns red.
- permit a half-issued task/capability pair and verify P24 turns red.
- accept a failed receipt with no failure signal and verify P25 turns red.
- permit backward authority time, an implicit post-expiry grace interval, or post-release promotion and verify P26 turns red.

Mutation may be manual in this version; every named mutation must be demonstrated at least once before claiming proof.

## 10. Determinism checks

- Reverse and permute input orders, then compare canonical output bytes.
- Run each seeded scenario twice and compare authority log, projection, and receipt bytes.
- Serialize independent equivalent objects and compare bytes.
- Prove caller-owned mutable collections cannot change constructed records.
- Rebuild projections from the event log and compare to live projection bytes after every generated transition sequence.

Serializing the same object twice is insufficient proof of input-order independence.

## 11. Pass gate

The simulator proof passes only when:

1. all P01–P26 properties pass;
2. all transition matrices are complete and unexpected transitions deny;
3. every required RED state was observed before GREEN implementation;
4. named false-green mutations make the relevant tests fail;
5. two deterministic runs produce byte-identical authority logs and projections;
6. no fixture contains private data, absolute home paths, raw transcripts, or literal secret signatures;
7. no network, subprocess, real CLI, real model, key, secret, node, or service is used;
8. exact schema version, test count, seed set, and artifact hashes are reported from real execution.

## 12. What this proof will not establish

Even a full pass will not prove:

- cryptographic security;
- OS, VM, or container isolation;
- actual CLI conformance;
- provider privacy or retention behavior;
- semantic correctness of model-generated work;
- safe secret injection;
- remote-node safety;
- production performance or token cost;
- automatic failover safety.

Those remain separate later gates.

## 13. Implementation gate

Simulator source location, dependency choice, branch/repository target, and exact test commands are intentionally deferred until the operator approves the written spec. The separate human decision plane remains untouched.
