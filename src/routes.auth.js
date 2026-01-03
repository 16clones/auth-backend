import express from "express";
import { z } from "zod";
import { db, Timestamp, FieldValue } from "./firestore.js";
import {
  randomToken,
  sha256Hex,
  hashSecret,
  verifySecret,
  verifyEd25519Signature
} from "./crypto.js";
import { SignJWT, importPKCS8 } from "jose";

const router = express.Router();

// =========================
// CONFIG (lazy / env-safe)
// =========================
const ACCESS_TOKEN_MINUTES = Number(process.env.ACCESS_TOKEN_MINUTES ?? 10);
const CHALLENGE_TTL_SECONDS = Number(process.env.CHALLENGE_TTL_SECONDS ?? 90);
const REFRESH_ROTATION_GRACE_SECONDS = Number(process.env.REFRESH_ROTATION_GRACE_SECONDS ?? 20);

function getJwtPrivateKeyPem() {
  const key = process.env.JWT_PRIVATE_KEY_PEM;
  if (!key) throw new Error("Missing JWT_PRIVATE_KEY_PEM");
  return key;
}

function getJwtConfig() {
  return {
    jwtIssuer: process.env.JWT_ISSUER ?? "your-api",
    jwtAudience: process.env.JWT_AUDIENCE ?? "your-app"
  };
}

// --- Helpers ---
async function mintAccessToken({ userId, sessionId, deviceId }) {
  const { jwtIssuer, jwtAudience } = getJwtConfig();

  const jwtPrivateKeyPem = getJwtPrivateKeyPem();
  const privateKey = await importPKCS8(jwtPrivateKeyPem.replace(/\\n/g, "\n"), "EdDSA");

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ACCESS_TOKEN_MINUTES * 60;

  return new SignJWT({
    sid: sessionId,
    did: deviceId
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(jwtIssuer)
    .setAudience(jwtAudience)
    .setSubject(userId)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);
}

async function findUserByAccessKey(accessKey) {
  // Access keys stored hashed (argon2id) and indexed by sha256 lookup for search.
  const lookup = sha256Hex(accessKey);
  const snap = await db.collection("accessKeys").where("lookup", "==", lookup).limit(1).get();
  if (snap.empty) return null;

  const doc = snap.docs[0];
  const data = doc.data();

  const ok = await verifySecret(data.accessKeyHash, accessKey);
  if (!ok) return null;

  return {
    userId: data.userId,
    accessKeyId: doc.id,
    usedAt: data.usedAt ?? null,
    expiresAt: data.expiresAt ?? null
  };
}

// --- Schemas ---
const StartSchema = z.object({
  accessKey: z.string().min(6),
  deviceId: z.string().min(6),
  // Ed25519 public key in PEM. Swift will generate and send on first login.
  devicePublicKeyPem: z.string().min(40)
});

const FinishSchema = z.object({
  challengeId: z.string().min(10),
  deviceId: z.string().min(6),
  signatureB64Url: z.string().min(20)
});

const RefreshSchema = z.object({
  refreshToken: z.string().min(20),
  deviceId: z.string().min(6)
});

// --- Routes ---

// 1) Start: validate accessKey and register/verify device public key, enforce one-time/expiry, burn key, then return a challenge nonce
router.post("/auth/start", async (req, res) => {
  const parsed = StartSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_INPUT" });

  const { accessKey, deviceId, devicePublicKeyPem } = parsed.data;

  const user = await findUserByAccessKey(accessKey);
  if (!user) return res.status(401).json({ error: "INVALID_CREDENTIALS" });

  // --- STEP 4: Enforce one-time / expiring access keys ---
  if (user.usedAt) {
    return res.status(401).json({ error: "ACCESS_KEY_ALREADY_USED" });
  }
  if (user.expiresAt && user.expiresAt.toMillis() < Date.now()) {
    return res.status(401).json({ error: "ACCESS_KEY_EXPIRED" });
  }

  // Upsert device: bind deviceId -> userId + public key (reject key changes unless you explicitly allow rotation)
  const deviceRef = db.collection("devices").doc(deviceId);

  // Transaction ensures consistent device binding
  let deviceError = null;

try {
  await db.runTransaction(async (tx) => {
    const deviceRef = db.collection("devices").doc(deviceId);
    const d = await tx.get(deviceRef);

    if (!d.exists) {
      tx.set(deviceRef, {
        userId: user.userId,
        publicKeyPem: devicePublicKeyPem,
        createdAt: FieldValue.serverTimestamp(),
        lastSeenAt: FieldValue.serverTimestamp()
      });
      return;
    }

    const data = d.data();
    if (data.userId !== user.userId) {
      throw new Error("DEVICE_ALREADY_BOUND");
    }
    if (data.publicKeyPem !== devicePublicKeyPem) {
      throw new Error("PUBLIC_KEY_MISMATCH");
    }

    tx.update(deviceRef, { lastSeenAt: FieldValue.serverTimestamp() });
  });
} catch (e) {
  if (e.message === "DEVICE_ALREADY_BOUND") {
    return res.status(403).json({ error: "DEVICE_BOUND_TO_OTHER_USER" });
  }
  if (e.message === "PUBLIC_KEY_MISMATCH") {
    return res.status(403).json({ error: "DEVICE_KEY_CHANGED_RELOGIN_REQUIRED" });
  }
  throw e;
}

  // Burn access key (one-time use) AFTER device binding succeeds
  await db.collection("accessKeys").doc(user.accessKeyId).update({
    usedAt: FieldValue.serverTimestamp()
  });

  const challengeId = randomToken(24);
  const nonce = randomToken(32);

  const expiresAt = Timestamp.fromMillis(Date.now() + CHALLENGE_TTL_SECONDS * 1000);

  await db.collection("challenges").doc(challengeId).set({
    userId: user.userId,
    deviceId,
    nonce,
    expiresAt,
    createdAt: FieldValue.serverTimestamp()
  });

  return res.json({
    challengeId,
    nonce,
    expiresInSeconds: CHALLENGE_TTL_SECONDS
  });
});

// 2) Finish: verify signature over the challenge, then issue access + refresh (rotating)
router.post("/auth/finish", async (req, res) => {
  const parsed = FinishSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_INPUT" });

  const { challengeId, deviceId, signatureB64Url } = parsed.data;

  const chalRef = db.collection("challenges").doc(challengeId);
  const chalDoc = await chalRef.get();
  if (!chalDoc.exists) return res.status(400).json({ error: "CHALLENGE_NOT_FOUND" });

  const chal = chalDoc.data();
  if (chal.deviceId !== deviceId) return res.status(400).json({ error: "CHALLENGE_DEVICE_MISMATCH" });
  if (chal.expiresAt.toMillis() < Date.now()) return res.status(400).json({ error: "CHALLENGE_EXPIRED" });

  const deviceDoc = await db.collection("devices").doc(deviceId).get();
  if (!deviceDoc.exists) return res.status(400).json({ error: "DEVICE_NOT_REGISTERED" });

  const device = deviceDoc.data();
  if (device.userId !== chal.userId) return res.status(403).json({ error: "DEVICE_NOT_OWNED" });

  // message to sign must be stable
  const message = `AUTH_CHALLENGE\n${challengeId}\n${deviceId}\n${chal.nonce}\n`;
  const ok = verifyEd25519Signature({
    publicKeyPem: device.publicKeyPem,
    message,
    signatureB64Url
  });
  if (!ok) return res.status(401).json({ error: "BAD_SIGNATURE" });

  // Consume challenge (single-use)
  await chalRef.delete();

  // Create session with rotating refresh token
  const sessionId = randomToken(18);
  const refreshToken = randomToken(32);

  const refreshLookup = sha256Hex(refreshToken);
  const refreshHash = await hashSecret(refreshToken);

  await db.collection("sessions").doc(sessionId).set({
    userId: chal.userId,
    deviceId,
    // current refresh
    refreshLookup,
    refreshHash,
    // previous refresh (for reuse detection)
    prevRefreshLookup: null,
    prevRotatedAt: null,

    createdAt: FieldValue.serverTimestamp(),
    rotatedAt: FieldValue.serverTimestamp(),
    revokedAt: null
  });

  const accessToken = await mintAccessToken({
    userId: chal.userId,
    sessionId,
    deviceId
  });

  return res.json({
    accessToken,
    refreshToken,
    expiresInMinutes: ACCESS_TOKEN_MINUTES
  });
});

// 3) Refresh: rotate refresh token; if old token is reused => revoke
router.post("/auth/refresh", async (req, res) => {
  const parsed = RefreshSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "INVALID_INPUT" });

  const { refreshToken, deviceId } = parsed.data;

  const lookup = sha256Hex(refreshToken);

  const snap = await db
    .collection("sessions")
    .where("deviceId", "==", deviceId)
    .where("refreshLookup", "==", lookup)
    .limit(1)
    .get();

  // If not found as current refresh, check if it matches previous (possible replay)
  if (snap.empty) {
    const prevSnap = await db
      .collection("sessions")
      .where("deviceId", "==", deviceId)
      .where("prevRefreshLookup", "==", lookup)
      .limit(1)
      .get();

    if (!prevSnap.empty) {
      // Reuse detected => revoke session hard
      const sdoc = prevSnap.docs[0];
      await sdoc.ref.update({ revokedAt: FieldValue.serverTimestamp() });
      return res.status(401).json({ error: "REFRESH_REUSE_DETECTED_SESSION_REVOKED" });
    }
    return res.status(401).json({ error: "INVALID_REFRESH" });
  }

  const sessionDoc = snap.docs[0];
  const session = sessionDoc.data();

  if (session.revokedAt) return res.status(401).json({ error: "SESSION_REVOKED" });
  if (session.deviceId !== deviceId) return res.status(401).json({ error: "DEVICE_MISMATCH" });

  // Verify refresh token against argon2 hash (defense-in-depth; lookup is only for search)
  const ok = await verifySecret(session.refreshHash, refreshToken);
  if (!ok) return res.status(401).json({ error: "INVALID_REFRESH" });

  // Rotate
  const newRefreshToken = randomToken(32);
  const newLookup = sha256Hex(newRefreshToken);
  const newHash = await hashSecret(newRefreshToken);

  await sessionDoc.ref.update({
    prevRefreshLookup: session.refreshLookup,
    prevRotatedAt: FieldValue.serverTimestamp(),
    refreshLookup: newLookup,
    refreshHash: newHash,
    rotatedAt: FieldValue.serverTimestamp()
  });

  const accessToken = await mintAccessToken({
    userId: session.userId,
    sessionId: sessionDoc.id,
    deviceId
  });

  return res.json({
    accessToken,
    refreshToken: newRefreshToken,
    expiresInMinutes: ACCESS_TOKEN_MINUTES
  });
});

export default router;
