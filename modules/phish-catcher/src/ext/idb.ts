/**
 * Minimal IndexedDB persistence for the MV3 service worker (doc 07 §6.3):
 * the signed bundle + policy + consent/options state rehydrate on wake
 * (<100 ms budget), and the redacted-report queue (ring buffer, max 500,
 * drop oldest first, §5.4) survives service-worker suspension.
 */

const DB_NAME = "aegisbastion-phish-catcher";
const DB_VERSION = 1;
const KV_STORE = "kv";
const REPORT_STORE = "reports";
const REPORT_CAP = 500;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KV_STORE)) db.createObjectStore(KV_STORE);
      if (!db.objectStoreNames.contains(REPORT_STORE)) {
        db.createObjectStore(REPORT_STORE, { autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
  });
}

function tx<T>(db: IDBDatabase, store: string, mode: IDBTransactionMode, op: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const req = op(t.objectStore(store));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB op failed"));
  });
}

export async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  try {
    return (await tx(db, KV_STORE, "readonly", (s) => s.get(key))) as T | undefined;
  } finally {
    db.close();
  }
}

export async function idbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  try {
    await tx(db, KV_STORE, "readwrite", (s) => s.put(value, key));
  } finally {
    db.close();
  }
}

/** Enqueue a redacted report; trim to the 500-entry ring (§5.4). */
export async function idbEnqueueReport(report: unknown): Promise<void> {
  const db = await openDb();
  try {
    await tx(db, REPORT_STORE, "readwrite", (s) => s.add(report));
    const count = await tx(db, REPORT_STORE, "readonly", (s) => s.count());
    if (count > REPORT_CAP) {
      const excess = count - REPORT_CAP;
      await new Promise<void>((resolve, reject) => {
        const t = db.transaction(REPORT_STORE, "readwrite");
        const cursorReq = t.objectStore(REPORT_STORE).openCursor();
        let deleted = 0;
        cursorReq.onsuccess = () => {
          const cursor = cursorReq.result;
          if (cursor && deleted < excess) {
            cursor.delete();
            deleted++;
            cursor.continue();
          } else {
            resolve();
          }
        };
        cursorReq.onerror = () => reject(cursorReq.error ?? new Error("trim failed"));
      });
    }
  } finally {
    db.close();
  }
}

/** Drain up to `n` queued reports (opportunistic flush, §5.4). */
export async function idbDrainReports(n: number): Promise<unknown[]> {
  const db = await openDb();
  try {
    return await new Promise<unknown[]>((resolve, reject) => {
      const out: unknown[] = [];
      const t = db.transaction(REPORT_STORE, "readwrite");
      const cursorReq = t.objectStore(REPORT_STORE).openCursor();
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        if (cursor && out.length < n) {
          out.push(cursor.value);
          cursor.delete();
          cursor.continue();
        } else {
          resolve(out);
        }
      };
      cursorReq.onerror = () => reject(cursorReq.error ?? new Error("drain failed"));
    });
  } finally {
    db.close();
  }
}

export async function idbReportCount(): Promise<number> {
  const db = await openDb();
  try {
    return await tx(db, REPORT_STORE, "readonly", (s) => s.count());
  } finally {
    db.close();
  }
}
