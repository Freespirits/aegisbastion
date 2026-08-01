/**
 * Persistence interface for herald. The pipeline only ever talks to this
 * interface: PostgresStore (services/alert/src/db/pgstore.ts) in production,
 * MemoryStore (db/memory.ts) in unit tests. Table shapes are
 * db/migrations/000005_alert.up.sql.
 */
export {};
