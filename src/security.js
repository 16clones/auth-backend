import rateLimit from "express-rate-limit";
import helmet from "helmet";

export const helmetMiddleware = helmet({
  contentSecurityPolicy: false
});

export const authRateLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});

export const strictRateLimit = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});
