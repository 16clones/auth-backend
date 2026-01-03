import express from "express";
import { db, FieldValue } from "./firestore.js";
import { randomToken, sha256Hex, hashSecret } from "./crypto.js";

const router = express.Router();

/**
 * POST /auth/keygen
 * Generates a new access key
 */
router.post("/auth/keygen", async (req, res) => {
  // In production, protect this route (admin auth, IP allowlist, etc.)
  const userId = req.body?.userId ?? "test_user_1";

  // 1) Generate secure random key
  const rawKey = `AK_${randomToken(32)}`;

  // 2) Hash for lookup + verification
  const lookup = sha256Hex(rawKey);
  const accessKeyHash = await hashSecret(rawKey);

  // 3) Store hashed key ONLY
  await db.collection("accessKeys").add({
    userId,
    lookup,
    accessKeyHash,
    createdAt: FieldValue.serverTimestamp(),
    expiresAt: null,      // optional
    usedAt: null          // optional
  });

  // 4) Return plaintext ONCE
  return res.json({
    accessKey: rawKey,
    userId
  });
});

export default router;
