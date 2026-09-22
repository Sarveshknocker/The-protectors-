// Typed, validated configuration. Import `env` everywhere instead of process.env.
// The process refuses to start with missing/weak secrets — fail fast, never fall back to defaults for secrets.
// deps: npm i zod   (Next.js: put this in a server-only module: import 'server-only')
import { z } from 'zod';

const csv = z.string().default('').transform((s) => s.split(',').map((x) => x.trim()).filter(Boolean));

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().url(),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters (use `openssl rand -base64 48`)'),
  CORS_ORIGINS: csv,
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  // Optional integrations: keep optional here, validate where used.
  STRIPE_SECRET_KEY: z.string().startsWith('sk_').optional(),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Print variable names only — never values.
  console.error('Invalid environment configuration:\n' + parsed.error.issues.map((i) => ` - ${i.path.join('.')}: ${i.message}`).join('\n'));
  process.exit(1);
}

export const env = Object.freeze(parsed.data);
export const isProd = env.NODE_ENV === 'production';
