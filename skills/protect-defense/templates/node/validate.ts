// Schema validation middleware (zod). deps: npm i zod
// Usage:
//   const CreateOrder = { body: z.object({ productId: z.string().uuid(), quantity: z.number().int().min(1).max(100) }).strict() };
//   router.post('/orders', validate(CreateOrder), handler);   // handler reads req.valid.body (typed)
// .strict() rejects unknown keys → blocks mass assignment (role, isAdmin, price, userId…).
import type { NextFunction, Request, Response } from 'express';
import { z, type ZodTypeAny } from 'zod';

type Schemas = { body?: ZodTypeAny; query?: ZodTypeAny; params?: ZodTypeAny };

declare module 'express-serve-static-core' {
  interface Request { valid: { body?: unknown; query?: unknown; params?: unknown } }
}

export function validate(schemas: Schemas) {
  return (req: Request, res: Response, next: NextFunction) => {
    const valid: Request['valid'] = {};
    for (const key of ['params', 'query', 'body'] as const) {
      const schema = schemas[key];
      if (!schema) continue;
      const result = schema.safeParse(req[key]);
      if (!result.success) {
        return res.status(400).type('application/problem+json').json({
          type: 'about:blank',
          title: 'Invalid request',
          status: 400,
          errors: result.error.issues.map((i) => ({ in: key, path: i.path.join('.'), message: i.message })),
          requestId: req.id,
        });
      }
      valid[key] = result.data;
    }
    req.valid = valid;
    next();
  };
}

// Reusable primitives
export const id = z.string().uuid();
export const email = z.string().trim().toLowerCase().email().max(254);
export const password = z.string().min(12).max(128);
export const pagination = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});
export const safeText = (max = 2000) => z.string().trim().max(max);
