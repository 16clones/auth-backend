import crypto from "crypto";
import argon2 from "argon2";

export function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

export function randomToken(bytes = 32) {
  return b64url(crypto.randomBytes(bytes));
}

export function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function sha256B64Url(input) {
  return b64url(crypto.createHash("sha256").update(input).digest());
}

export async function hashSecret(secret) {
  return argon2.hash(secret, { type: argon2.argon2id });
}

export async function verifySecret(hash, secret) {
  return argon2.verify(hash, secret);
}

// Canonical request string to sign (client + server must match EXACTLY)
export function canonicalRequest({ method, path, timestamp, nonce, bodyHash }) {
  return `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}\n`;
}

// Verify Ed25519 signature (base64url)
export function verifyEd25519Signature({ publicKeyPem, message, signatureB64Url }) {
  const sig = Buffer.from(signatureB64Url, "base64url");
  const keyObj = crypto.createPublicKey(publicKeyPem);
  return crypto.verify(null, Buffer.from(message, "utf8"), keyObj, sig);
}
