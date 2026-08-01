# db/ — AegisBastion data plane (PostgreSQL 16)

golang-migrate compatible migrations for the MVP-A single-instance data
plane. One database (`aegisbastion`), one schema per bounded context:

| Migration | Schema(s) | Owner (design doc) | Contents |
|---|---|---|---|
| `000001_platform_core` | `platform` | doc 01 | missions, plans, tasks (scheduler queue), agents (registry), outbox, kill_switches |
| `000002_gatekeeper` | `gatekeeper` | doc 11 | roe_records (+ effective targets, immutability trigger), rbac_roles/bindings, approvals (+votes), authz_decisions, issued_tokens, revocations, hash-chained append-only audit_events (daily partitions), `aegisbastion_audit_writer` insert-only role |
| `000003_data_platform` | `dp`, `tenancy` | doc 09 / doc 02 §4.1 (Ruling C4) | assets, asset_edges, finding_provenance, findings (monthly partitions; lifecycle states per doc 04 §7.3), finding_state_transitions, ingest_batches, audit_outbox; tenants, workspaces, grants, retention_profiles |
| `000004_module_stores` | `discover`, `monitor`, `detect` | docs 02/03/04 | discover working store + quarantine + audit_spool; monitor watch/snapshot/change-event stores; detect fallback findings + fingerprint cache + suppressions |

## Applying

The compose infra tier applies these automatically via the `db-migrate`
one-shot service (`migrate/migrate:4`):

```sh
cd deploy
docker compose --profile infra up -d
```

Against a running Postgres by hand (Docker, no local toolchain needed):

```sh
docker run --rm --network aegisbastion-mvp-a_default \
  -v "$PWD/../db/migrations:/migrations:ro" migrate/migrate:4 \
  -path=/migrations \
  -database "postgres://aegisbastion:aegisbastion-dev@postgres:5432/aegisbastion?sslmode=disable" \
  up        # or: goto N | down 1 | version | force N
```

## Conventions

- Files: `NNNNNN_name.up.sql` / `NNNNNN_name.down.sql`, applied in order.
- Each migration runs in an explicit transaction (`BEGIN; … COMMIT;`) —
  do not add statements that cannot run in a transaction.
- IDs: text ULIDs on the platform/gatekeeper side (`msn_…`, `tsk_…`,
  `roe_…`, `tok_…`); UUIDv7 on the data-platform side (doc 09 §12).
- RoE/approval/token/audit tables exist **only** in the `gatekeeper`
  schema (Ruling B — gatekeeper is the single PDP). The `platform` schema
  references RoEs by `roe_id`/`roe_version` and stores no RoE state.
- `dp.findings.state` uses the doc 04 §7.3 lifecycle enum
  (`new, triaged, validating, confirmed_open, remediation_claimed,
  verified_closed, false_positive, accepted_risk, reopened`) — doc 00 Ruling
  C4 makes doc 04 §7.3 the lifecycle of record, superseding the state CHECK
  sketched in doc 09 §4.2.
- Partitioned tables (`gatekeeper.audit_events` daily, `dp.findings`
  monthly, `monitor.snapshots_history` / `monitor.change_events` monthly)
  ship with DEFAULT partitions so inserts never fail; a partition
  pre-creation job is a later-wave operations concern.
