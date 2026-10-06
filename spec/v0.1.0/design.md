# Normative Design — Single Coordinator Authority Proof

Schema version: `0.1.0`
Status: validated design ready for operator review; simulator not implemented

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

## 1. Goal

Prove that one operator-facing coordinator identity can coordinate replaceable workers without giving any model, worker, host, adapter, or interface canonical promotion authority.

The design succeeds only if the proof is:

- provider-neutral;
- model-independent at security boundaries;
- deterministic under replay and restore;
- deny-by-default;
- explicit about unknown evidence;
- independent of real node enrollment, secrets, services, and production data.

## 2. Scope

This design defines:

1. identity layers and ownership;
2. canonical execution-state classes;
3. strict task, capability, artifact, receipt, promotion, and authority-event contracts;
4. authority epoch and lease semantics;
5. promotion validation order;
6. deterministic fake-worker and adversarial test requirements;
7. the one-way integration boundary with a separate human decision plane.

This design does not define:

- a general agent framework;
- a new project or decision ledger;
- an inbox or user interface;
- a production daemon;
- a cryptographic token format;
- an always-on host;
- automatic failover;
- a remote worker protocol;
- secret storage or production credential injection;
- a public product name.

## 3. Selected architecture

### 3.1 Approach A

The accepted approach keeps the proof in an isolated research repository as a normative package. No change is made to the separate human decision plane.

This is preferred because it:

- leaves the decision plane's accepted documentation unchanged;
- avoids a second source of truth;
- lets schemas fail cheaply before runtime decisions become expensive;
- keeps code, dependency, enrollment, and service choices behind later approval gates.

### 3.2 Rejected approaches

**Direct implementation inside the decision plane now** is rejected because the decision plane's first phase explicitly excludes protocol standardization and broad production architecture.

**A separate production runtime/repository now** is rejected because it would duplicate decision-plane and coordinator semantics before the integration contract is stable.

## 4. Two canonical domains, no competing truth

The authority core does not replace the decision plane.

### 4.1 Human decision domain

The operator and the decision plane are canonical for:

- human intent and purpose;
- values and non-delegable boundaries;
- risk acceptance;
- acceptable evidence definitions;
- irreversible and high-consequence choices;
- stop, pivot, and recovery authority;
- learning about future human decisions.

### 4.2 Execution authority domain

The authority core is canonical only for:

- task issuance;
- policy digest binding;
- capability issuance and revocation;
- authority epochs and writer leases;
- run and receipt acceptance state;
- artifact identity;
- promotion or rejection of bounded execution results;
- append-only execution authority events.

### 4.3 Bridge rule

Every governed task MUST contain an immutable `decision_ref` that points to its authorizing operator decision or an explicitly pre-authorized policy decision. The reference is opaque to the authority core; this package does not define, parse, migrate, or standardize decision-object serialization.

The authority core MAY return `EVIDENCE`, `OUTCOME`, and `LEARNING` proposals to the decision plane. It MUST NOT silently rewrite decision-plane intent, boundary, risk, or decision records.

In this version there is no automatic two-way synchronization. A bridge artifact is a proposal until accepted by the owner of the target domain.

## 5. Identity contract

### 5.1 Coordinator identity

The coordinator is one logical operator-facing identity. It provides continuity of coordination and explanation across surfaces, models, tools, and machines.

The coordinator is not:

- one permanently privileged process;
- a root signing key inside an LLM context;
- a hostname;
- an agent-runtime session;
- a provider account;
- a worker identity;
- a canonical database.

### 5.2 Identity layers

| Layer | Stable meaning | May do | Must not do |
|---|---|---|---|
| Operator | Root human authority | approve policy, recovery, and human decisions | expose root material to a model |
| Coordinator identity | Single operator-facing coordinator | decompose, route, explain, request authority | mint authority or self-approve promotion |
| Authority writer | One current, instance-bound canonical execution writer | issue tasks, revoke, verify, promote | operate outside current epoch/lease |
| Node identity | Enrolled execution host | authenticate a host and advertise capabilities | imply task authorization |
| Process identity | One running worker process | execute one bounded run | inherit unrelated node authority |
| Adapter identity | Pinned adapter contract and binary | translate structured task/run events | hide unsupported capability or version drift |
| Surface identity | chat, voice, TUI, terminal session | submit intent and display state | become canonical authority or fork the coordinator |

### 5.3 Root rules

- Root signing or recovery secrets MUST remain outside model-visible memory, prompts, task packets, logs, receipts, and artifacts.
- A worker MUST NOT enroll itself, extend its own capability, renew an authority lease, weaken policy, or promote its own output.
- Node authentication MUST NOT be treated as task authorization.
- Task authorization MUST NOT be treated as proof of node integrity.
- Adapter updates change effective execution identity and MUST trigger compatibility revalidation.

## 6. State ownership

| State | Canonical owner | Mutability | Worker visibility |
|---|---|---|---|
| Human intent and decisions | Operator / decision plane | decision-plane rules | referenced, not rewritten |
| Approved policy semantics | Operator-approved policy registry | versioned | digest plus relevant slice |
| Authority epoch and lease | Authority core | append-only transitions | current binding only |
| Task envelope | Authority core | immutable after issue | bounded task packet |
| Capability claim | Capability broker under authority core | immutable; revocable | governor/runner only |
| Runtime workspace | Worker sandbox | ephemeral | scoped |
| Artifact bytes | Content-addressed artifact store | immutable | explicit references only |
| Receipt proposal | Worker/adapter/governor evidence lane | append-only evidence | producer may submit |
| Verified receipt state | Receipt verifier / authority core | append-only decision | status projection only |
| Promotion proposal | Worker or coordinator proposal lane | immutable | submit only |
| Promotion decision | Authority core | append-only | result projection only |
| Provider sessions/caches | Adapter/runtime | ephemeral | never canonical |
| UI/read models | Rebuildable projections | disposable | surface-specific |

No record class may have two canonical writers. Physical storage MAY be distributed later, but semantic mutation ownership MUST remain singular and explicit.

Run lifecycle state is ephemeral governor evidence, not an `authority_event` state-machine domain. Only a verified/rejected/quarantined execution receipt crosses into the canonical authority log. This keeps process chatter outside canonical state while preserving terminal evidence.

## 7. Contract family

The strict schema bundle defines eight document kinds:

1. `authority_lease`
2. `task_envelope`
3. `capability_claim`
4. `artifact_manifest`
5. `execution_receipt`
6. `promotion_proposal`
7. `promotion_decision`
8. `authority_event`

`policy_evidence` and `restore_evidence` are authority-event object-kind labels, not additional document kinds. In schema version `0.1.0` they are opaque content-addressed evidence: the authority event binds their exact digest and transition, but the authority core does not parse or standardize their internal serialization. They have no mutation power by themselves. A future typed policy/checkpoint contract requires a new review and schema-version gate.

Every document MUST include:

- `kind` and `schema_version`;
- `operator_id`;
- one stable object ID;
- authority binding where relevant;
- strict known fields only;
- no secret value, raw prompt, raw transcript, provider chat history, or arbitrary extension payload.

Unknown fields MUST be rejected. Semantic extensions require a schema-version change rather than an ungoverned `metadata` object.

### 7.1 Authority lease contract

An `authority_lease` is an immutable, governor-only record that makes writer tenure reconstructable without hidden process state.

It MUST bind:

- one Operator or approved-policy `authorization_ref`;
- expected prior authority state;
- writer ID, epoch, lease generation, stable lease ID, and unique lease-record ID;
- acquisition, renewal, reissue, or recovery action;
- issue, validity-start, and expiry times;
- active policy digest and prior authority head;
- previous lease-record ID where one exists;
- simulation encoding profile and nonce.

A renewal MUST create a new lease-record ID while preserving writer, epoch, generation, and stable lease ID. A reissue MUST use a new stable lease ID and higher lease generation. Recovery or writer takeover MUST use a higher authority epoch. Lease expiry is derived from the immutable record and authority-core time; an expired writer cannot append an expiry event on its own behalf.

`expires_at` is the sole canonical lease-validity boundary. At explicit authority time `as_of >= expires_at`, the lease is expired and promotion MUST fail closed. This version defines no implicit heartbeat grace period. Heartbeat scheduling MAY be operational policy or adapter guidance, but it is not authority state and cannot extend a lease without a newly accepted immutable renewal record. Adding grace semantics later requires an explicit schema-version and security-review gate.

Timestamp ordering and action-specific lease relationships are cross-record semantic checks and MUST be exercised by the property-test model.

## 8. Task envelope

A task envelope is the smallest model-visible work packet that preserves authority and acceptance semantics.

It MUST bind:

- one `decision_ref`;
- one task ID and idempotency key;
- current authority epoch and lease generation;
- current policy digest and expected authority-log head;
- one capability claim ID;
- one node/adapter audience;
- one bounded goal;
- one opaque workspace reference;
- content-addressed input and context references;
- required actions and adapter features;
- explicit resource budget;
- explicit acceptance checks;
- issue and expiry times;
- a nonce.

It MUST NOT contain:

- an absolute private path;
- credential material;
- environment dumps;
- full conversation history;
- raw provider session state;
- implicit permission such as `all`, `any`, or unrestricted wildcard rights.

## 9. Capability claim

A capability claim is a deny-by-default authorization object interpreted outside the model.

It MUST bind:

- operator, task, epoch, lease generation, policy, subject, and audience;
- a closed set of allowed actions;
- one workspace reference;
- allowed input artifact references;
- resource ceilings;
- validity interval;
- revocation ID;
- delegation depth;
- optional opaque broker-handle references marked governor-only.

A child capability MUST be a monotonic attenuation of its parent across:

- action set;
- subject and audience;
- workspace;
- artifact set;
- validity interval;
- wall time, tool calls, output bytes, token bounds, network requests, and process count;
- egress destination aliases;
- broker handles;
- delegation depth.

No score, model confidence, urgency flag, or adapter self-report can override attenuation or hard denial.

The schema uses `simulation_unsigned_v1`. This proves semantics only; it is not a production credential format.

## 10. Artifacts and receipts

### 10.1 Artifact manifest

Artifact bytes live outside the model contract. The manifest records content digest, byte length, media type, classification, immutable storage reference, producer identity, and provenance.

A digest proves byte identity only. It does not prove semantic correctness, safety, origin, or acceptance.

Every artifact that enters a receipt, promotion proposal, or promotion decision MUST use an immutable pin containing exactly `artifact_id`, `content_digest`, and `manifest_digest`. A bare artifact ID is insufficient. The authority writer verifies both digests before decision creation; the authority event then binds the decision digest. Replacing artifact bytes or a manifest under the same ID MUST fail `ARTIFACT_MISMATCH` without changing the authority head.

### 10.2 Execution receipt

A receipt is an evidence proposal. It MUST bind:

- task, capability, epoch, lease generation, run, node, adapter, workspace, and policy;
- process start and finish times;
- one terminal run state;
- externally observed process result;
- classified observations;
- produced artifact pins containing artifact ID, content digest, and manifest digest;
- usage metrics with an authority class;
- an anti-replay nonce.

Receipt observation trust classes are ordered by provenance, not by persuasion:

1. `governor_observed`
2. `adapter_parsed`
3. `tool_self_reported`
4. `model_asserted`

A lower class cannot satisfy an acceptance check requiring a higher class. `model_asserted` is never sufficient evidence by itself.

Unknown usage, cost, process state, or evidence MUST remain `unknown`; zero MUST NOT substitute for unknown.

A `failed` receipt MUST contain at least one concrete failure signal: a non-zero exit code, a non-null terminating signal, a hard-budget breach, or a failed classified observation. Exit code zero does not force success when an acceptance check fails, but `failed` with exit zero, no signal, no budget breach, and all observations passing is invalid.

## 11. Promotion

### 11.1 Proposal

A worker or the coordinator MAY submit a promotion proposal that references receipts, pinned artifact identities, expected authority head, requested effect, and acceptance evidence.

A proposal has no mutation power.

### 11.2 Decision

Only the active authority writer MAY create a promotion decision and append the corresponding authority event.

The promotion decision is a pre-append immutable object. It MUST contain the prior authority head, but MUST NOT embed the future authority event ID or resulting authority head. The event references the decision digest; successful compare-and-append then returns `(decision_id, event_id, resulting_head)` as a rebuildable projection/API result. This avoids a circular decision-hash/event-hash dependency.

The authority core MUST validate in this order:

1. parse against the exact schema version;
2. verify operator and object bindings;
3. verify current authority epoch and lease generation;
4. verify authority lease using authority-core time;
5. verify task, capability, policy, audience, expiry, and revocation state;
6. verify capability attenuation and resource bounds;
7. verify receipt terminal state and evidence trust requirements;
8. recompute artifact-manifest digests and verify every artifact ID/content-digest/manifest-digest pin against immutable bytes;
9. verify expected prior authority head;
10. verify idempotency and replay cache;
11. run acceptance-specific checks;
12. atomically append one decision event or append one generic rejection event.

A rejection MUST leave canonical project/artifact state unchanged. Evidence MAY remain archived with rejected, stale, revoked, or quarantined status.

## 12. Authority epoch and lease

- `authority_epoch` is a monotonically increasing global fencing term.
- `lease_generation` is monotonically increasing within an epoch when a writer lease is replaced or reissued.
- Renewing the same valid lease extends expiry without changing generation. Renewal is the same instance-bound writer and logical lease term, not a new session; writer ID, epoch, generation, stable lease ID, and policy MUST remain unchanged.
- Any writer-instance or lease-ID replacement is a reissue, not a renewal, and MUST increment lease generation; takeover/recovery MUST also increment authority epoch.
- A current writer MAY voluntarily append `lease_released`; promotion then pauses in `NO_WRITER`, and any later acquisition uses a higher epoch.
- A writer takeover or Operator recovery MUST create a higher epoch.
- Promotion requires the exact current `(authority_epoch, lease_generation)` pair.
- A result issued before an epoch transition MAY remain evidence but MUST NOT promote after the transition.
- No automatic failover exists in this version.
- If no valid writer exists, intent MAY queue and pre-authorized workers MAY finish local work within unexpired capabilities, but canonical promotion MUST pause.

## 13. Failure semantics

The authority core fails closed with generic reason codes. Errors MUST NOT echo paths, secret-shaped values, raw payloads, expected digests, actual digests, or provider content.

Closed reason-code families:

- `SCHEMA_INVALID`
- `IDENTITY_MISMATCH`
- `AUTHORITY_STALE`
- `LEASE_EXPIRED`
- `CAPABILITY_INVALID`
- `CAPABILITY_REVOKED`
- `SCOPE_EXCEEDED`
- `BUDGET_EXCEEDED`
- `ADAPTER_UNSUPPORTED`
- `RECEIPT_UNVERIFIED`
- `ARTIFACT_MISMATCH`
- `EXPECTED_HEAD_MISMATCH`
- `REPLAY_DETECTED`
- `ACCEPTANCE_FAILED`
- `POLICY_MISMATCH`
- `RECOVERY_REQUIRED`

Malformed input MUST produce a denied/quarantined result, not crash the authority service.

## 14. Model and provider boundary

Models and provider sessions are untrusted reasoning/execution dependencies.

They MAY:

- receive the bounded goal, relevant policy slice, referenced artifact excerpts, and acceptance criteria;
- produce proposed artifacts and natural-language explanations.

They MUST NOT:

- receive root or broker secrets;
- decide capability validity;
- mutate policy;
- classify their own receipt as verified;
- append authority events;
- change expected prior state;
- convert missing telemetry into success;
- promote output.

Prompt injection is treated as untrusted data attempting to cross a capability boundary, not as a prompt-quality problem.

## 15. Token and context invariant

For a fixed task and fixed relevant state, adding idle nodes, installed adapters, or unrelated history MUST NOT change the serialized task envelope.

Model input SHOULD approximate:

`goal + policy slice + relevant state delta + selected artifact excerpts + adapter overhead`

It MUST NOT approximate:

`all history × all nodes × all agents`.

A conformance test MUST compare exact serialized task-envelope bytes before and after adding idle synthetic nodes.

## 16. Restore and projection

- Authority events, referenced canonical-object bytes, and pinned artifact manifests MUST be sufficient to rebuild disposable projections.
- Restore MUST preserve event order, sequence, previous-event digest, schema version, epoch, lease generation, revocation state, and idempotency records.
- A restore with a missing, duplicated, reordered, or altered event MUST enter `RECOVERY_REQUIRED`.
- Restoring a backup MUST NOT roll back policy or authority epoch silently.
- Provider sessions and caches are never required for restore.

## 17. Technology decisions deliberately deferred

This design does not select:

- Macaroons, Biscuit, JWT, COSE, OAuth, SPIFFE/SPIRE, or WIMSE token machinery;
- OPA, Cedar, or a custom policy engine;
- Rust or Python for a production daemon;
- SQLite, event sourcing middleware, or distributed consensus for production;
- a specific machine or cloud as the permanent authority host.

The fake-worker proof SHOULD use the smallest deterministic in-memory representation. Production technology selection follows demonstrated semantics, not the reverse.

## 18. Design acceptance criteria

The written design passes review only if:

1. every mutation has exactly one owner;
2. every execution object is bound to operator, task, policy, epoch, and expected prior state where applicable;
3. no worker path reaches canonical append or promotion;
4. every unknown or malformed condition has fail-closed semantics;
5. no contract has a field for secret values, raw prompts, transcripts, or arbitrary extension payloads;
6. the decision plane remains the human decision authority;
7. state-machine and property-test documents cover all twelve research invariants;
8. schema examples validate without external services;
9. the package introduces no implementation, dependency, service, node, secret, commit, or push side effect.

## 19. Review gate

After deterministic validation, the operator reviews this package. Simulator code and its implementation plan remain blocked until explicit approval of the written spec.
