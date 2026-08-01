/**
 * Live-infra smoke test (NOT part of `npm test`) — validates the SDK against
 * the real compose infra tier (NATS JetStream + MinIO):
 *
 *   cd deploy && docker compose --profile infra up -d
 *   node scripts/smoke-infra.mjs
 *
 * Covers: BusClient envelope publish + task.assign consumer ack flow,
 * control.kill core-NATS broadcast, and S3 manifest fetch/verify against
 * MinIO (token-manifests bucket). Uses only scratch subjects/keys and cleans
 * up after itself (consumer + object deleted on exit).
 */

import { createHash } from "node:crypto";
import { BusClient } from "../dist/index.js";
import { decodeControlKill, fetchAndVerifyManifest, createS3ManifestFetcher } from "../dist/index.js";

const NATS_URL = process.env.NATS_URL ?? "nats://localhost:4222";
const S3_ENDPOINT = process.env.S3_ENDPOINT ?? "http://localhost:9000";
const S3_ACCESS_KEY = process.env.S3_ACCESS_KEY ?? "aegisbastion";
const S3_SECRET_KEY = process.env.S3_SECRET_KEY ?? "aegisbastion-dev-secret";
const AGENT = `sdk-smoke-${Math.random().toString(36).slice(2, 8)}`;

let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
  if (!cond) failures++;
};

// --- MinIO manifest fetch/verify -------------------------------------------
const targets = ["https://api.acme.com/graphql", "203.0.113.10"];
const manifestBytes = JSON.stringify(targets);
const manifestSha = createHash("sha256").update(manifestBytes).digest("hex");
const key = `${AGENT}/targets.json`;

{
  const { S3Client, PutObjectCommand, DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  const s3 = new S3Client({
    endpoint: S3_ENDPOINT,
    region: "us-east-1",
    forcePathStyle: true,
    credentials: { accessKeyId: S3_ACCESS_KEY, secretAccessKey: S3_SECRET_KEY },
  });
  await s3.send(new PutObjectCommand({ Bucket: "token-manifests", Key: key, Body: manifestBytes }));

  const fetcher = createS3ManifestFetcher({
    endpoint: S3_ENDPOINT,
    accessKeyId: S3_ACCESS_KEY,
    secretAccessKey: S3_SECRET_KEY,
  });
  const verified = await fetchAndVerifyManifest(
    {
      hash_alg: "sha256",
      manifest_uri: `blob://token-manifests/${key}`,
      manifest_sha256: manifestSha,
      count: 2,
    },
    false,
    fetcher,
  );
  check("minio: manifest fetched, hash-verified, parsed (exact form)", verified.form === "exact" && verified.targets.length === 2);

  let hashRejected = false;
  try {
    await fetchAndVerifyManifest(
      { hash_alg: "sha256", manifest_uri: `blob://token-manifests/${key}`, manifest_sha256: "0".repeat(64) },
      false,
      fetcher,
    );
  } catch (err) {
    hashRejected = err.code === "MANIFEST_HASH_MISMATCH";
  }
  check("minio: tampered hash rejected (MANIFEST_HASH_MISMATCH)", hashRejected);

  await s3.send(new DeleteObjectCommand({ Bucket: "token-manifests", Key: key }));
}

// --- NATS bus: assignment consumer + control.kill ---------------------------
const bus = await BusClient.connect({ servers: NATS_URL });

{
  const { create } = await import("@bufbuild/protobuf");
  const { TaskAssignmentSchema } = await import("../dist/index.js");

  const received = [];
  const consumer = await bus.consumeAssignments(AGENT, async (delivery) => {
    received.push(delivery.assignment);
  });

  const assignment = create(TaskAssignmentSchema, {
    taskId: "tsk_smoke1",
    missionId: "msn_smoke",
    capability: "monitor.watch",
    targets: ["api.acme.com"],
  });
  await bus.publish(`task.assign.${AGENT}`, TaskAssignmentSchema, assignment, { missionId: "msn_smoke" });

  const deadline = Date.now() + 10_000;
  while (received.length === 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
  }
  check(
    "bus: task.assign envelope published, consumed, acked",
    received.length === 1 && received[0].taskId === "tsk_smoke1" && received[0].targets[0] === "api.acme.com",
  );
  await consumer.stop();

  // control.kill is a core NATS broadcast (no JetStream stream).
  const kills = [];
  const killSub = bus.subscribeKill((data) => kills.push(data));
  await bus.nc.publish("control.kill", new TextEncoder().encode("smoke-garbage"));
  const killDeadline = Date.now() + 5_000;
  while (kills.length === 0 && Date.now() < killDeadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
  const decoded = kills.length > 0 ? decodeControlKill(kills[0]) : null;
  check(
    "bus: control.kill broadcast received; unparseable ⇒ fail-safe GLOBAL kill",
    decoded !== null && "global" in decoded && decoded.global === true,
  );
  await killSub.stop();

  // Clean up the smoke consumer (stream messages expire with the stream policy).
  const { jetstreamManager } = await import("@nats-io/jetstream");
  const jsm = await jetstreamManager(bus.nc);
  await jsm.consumers.delete("TASK_ASSIGN", `agent-${AGENT}`).catch(() => {});
}

await bus.close();
console.log(failures === 0 ? "SMOKE OK" : `SMOKE FAILED (${failures})`);
process.exit(failures === 0 ? 0 : 1);
