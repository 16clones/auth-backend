import { jwtVerify, importSPKI } from "jose";
import { db, Timestamp, FieldValue } from "./firestore.js";
import { canonicalRequest, sha256B64Url, verifyEd25519Signature } from "./crypto.js";

const CLOCK_SKEW_MS = 60_000; // +/- 60s

// Lazily loaded + cached JWT public key (ESM-safe)
let cachedJwtPublicKey = null;

async function getJwtPublicKey() {
  if (cachedJwtPublicKey) return cachedJwtPublicKey;

  const pem = process.env.JWT_PUBLIC_KEY_PEM;
  if (!pem) {
    throw new Error(
      "Missing JWT_PUBLIC_KEY_PEM in .env (public key corresponding to JWT_PRIVATE_KEY_PEM)"
    );
  }

  cachedJwtPublicKey = await importSPKI(pem.replace(/\\n/g, "\n"), "EdDSA");
  return cachedJwtPublicKey;
}

function getJwtConfig() {
  // Read env lazily too (safe + supports hot reload)
  const jwtIssuer = process.env.JWT_ISSUER ?? "your-api";
  const jwtAudience = process.env.JWT_AUDIENCE ?? "your-app";
  const NONCE_TTL_SECONDS = Number(process.env.NONCE_TTL_SECONDS ?? 90);

  return { jwtIssuer, jwtAudience, NONCE_TTL_SECONDS };
}

export function requireAuthAndSignedRequest() {
  return async (req, res, next) => {
    try {
      const { jwtIssuer, jwtAudience, NONCE_TTL_SECONDS } = getJwtConfig();

      // 1) JWT
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (!token) return res.status(401).json({ error: "MISSING_TOKEN" });

      const publicKey = await getJwtPublicKey();
      const verified = await jwtVerify(token, publicKey, {
        issuer: jwtIssuer,
        audience: jwtAudience
      });

      const userId = verified.payload.sub;
      const sessionId = verified.payload.sid;
      const deviceId = verified.payload.did;

      if (!userId || !sessionId || !deviceId) {
        return res.status(401).json({ error: "BAD_TOKEN" });
      }

      // 2) Signed request headers
      const timestamp = req.header("X-Timestamp");
      const nonce = req.header("X-Nonce");
      const bodyHash = req.header("X-Body-SHA256");
      const signature = req.header("X-Signature");

      if (!timestamp || !nonce || !bodyHash || !signature) {
        return res.status(401).json({ error: "MISSING_SIGNATURE_HEADERS" });
      }

      const tsNum = Number(timestamp);
      if (!Number.isFinite(tsNum)) {
        return res.status(401).json({ error: "BAD_TIMESTAMP" });
      }

      const now = Date.now();
      if (Math.abs(now - tsNum) > CLOCK_SKEW_MS) {
        return res.status(401).json({ error: "TIMESTAMP_OUT_OF_RANGE" });
      }

      // Compute body hash server-side and compare
      const rawBody = req.rawBody ?? JSON.stringify(req.body ?? {});
      const computedHash = sha256B64Url(rawBody);
      if (computedHash !== bodyHash) {
        return res.status(401).json({ error: "BODY_HASH_MISMATCH" });
      }

      // Nonce single-use (per session)
      const nonceRef = db
        .collection("sessions")
        .doc(sessionId)
        .collection("nonces")
        .doc(nonce);

      const nonceDoc = await nonceRef.get();
      if (nonceDoc.exists) {
        return res.status(401).json({ error: "NONCE_REUSED" });
      }

      const expiresAt = Timestamp.fromMillis(Date.now() + NONCE_TTL_SECONDS * 1000);
      await nonceRef.set({
        createdAt: FieldValue.serverTimestamp(),
        expiresAt
      });

      // Verify signature with device public key
      const deviceDoc = await db.collection("devices").doc(deviceId).get();
      if (!deviceDoc.exists) {
        return res.status(401).json({ error: "DEVICE_NOT_FOUND" });
      }

      const device = deviceDoc.data();
      if (device.userId !== userId) {
        return res.status(401).json({ error: "DEVICE_NOT_OWNED" });
      }

      const message = canonicalRequest({
        method: req.method,
        path: req.originalUrl.split("?")[0],
        timestamp,
        nonce,
        bodyHash
      });

      const ok = verifyEd25519Signature({
        publicKeyPem: device.publicKeyPem,
        message,
        signatureB64Url: signature
      });

      if (!ok) {
        return res.status(401).json({ error: "BAD_REQUEST_SIGNATURE" });
      }

      // Attach trusted context
      req.auth = { userId, sessionId, deviceId };
      next();
    } catch (e) {
      // Optional: uncomment for debugging
      // console.error("AUTH ERROR:", e);
      return res.status(401).json({ error: "UNAUTHORIZED" });
    }
  };
}
