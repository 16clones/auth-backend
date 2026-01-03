import dotenv from "dotenv";
dotenv.config(); // MUST be first

import express from "express";
import { helmetMiddleware, authRateLimit, strictRateLimit } from "./security.js";
import authRoutes from "./routes.auth.js";
import keygenRoutes from "./routes.keygen.js";
import { requireAuthAndSignedRequest } from "./middleware.auth.js";

// 1️⃣ Initialize app FIRST
const app = express();

// 2️⃣ Middleware
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString("utf8");
  }
}));

app.use(helmetMiddleware);

// 3️⃣ Routes (ONLY after app exists)
app.use(authRateLimit);
app.use(authRoutes);
app.use(keygenRoutes);

// 4️⃣ Example protected route
app.post(
  "/protected/ping",
  strictRateLimit,
  requireAuthAndSignedRequest(),
  (req, res) => {
    res.json({ ok: true, auth: req.auth });
  }
);

// 5️⃣ Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// 6️⃣ Start server LAST
const port = Number(process.env.PORT ?? 8787);
app.listen(port, () => {
  console.log(`Secure auth server listening on :${port}`);
});
