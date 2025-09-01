import { z } from 'zod';

// IOC Types
export type IOCType = 'ip' | 'domain' | 'url' | 'hash';
export type Verdict = 'malicious' | 'suspicious' | 'harmless' | 'undetected' | 'unknown';

// Request Schemas
export const SubmitIOCRequestSchema = z.object({
  iocs: z.array(z.string().trim().min(1)).min(1).max(1000),
  label: z.string().optional(),
});

export type SubmitIOCRequest = z.infer<typeof SubmitIOCRequestSchema>;

// VirusTotal Response Normalization
export const VTNormalizedSchema = z.object({
  verdict: z.enum(['malicious', 'suspicious', 'harmless', 'undetected', 'unknown']),
  stats: z.object({
    malicious: z.number().default(0),
    suspicious: z.number().default(0),
    harmless: z.number().default(0),
    undetected: z.number().default(0),
    timeout: z.number().optional(),
  }),
  reputation: z.number().optional(),
  categories: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
  last_analysis_date: z.string().optional(),
  providers: z.array(z.object({
    engine: z.string(),
    category: z.string(),
    result: z.string().optional(),
  })).optional(),
});

export type VTNormalized = z.infer<typeof VTNormalizedSchema>;

// IOC Record Schema (for MongoDB)
export const IOCRecordSchema = z.object({
  _id: z.string(),
  ioc: z.string(),
  type: z.enum(['ip', 'domain', 'url', 'hash']),
  label: z.string().optional(),
  vt: z.object({
    raw: z.record(z.any()),
    normalized: VTNormalizedSchema,
  }),
  fetchedAt: z.date(),
  updatedAt: z.date(),
  cacheTtlSec: z.number(),
  meta: z.object({
    createdBy: z.string().optional(),
    caseId: z.string().optional(),
  }).optional(),
});

export type IOCRecord = z.infer<typeof IOCRecordSchema>;

// API Response Types
export const SubmitIOCResponseSchema = z.object({
  total: z.number(),
  created: z.number(),
  fromCache: z.number(),
  errors: z.array(z.string()),
  items: z.array(z.object({
    _id: z.string(),
    ioc: z.string(),
    type: z.enum(['ip', 'domain', 'url', 'hash']),
    verdict: z.enum(['malicious', 'suspicious', 'harmless', 'undetected', 'unknown']),
  })),
});

export type SubmitIOCResponse = z.infer<typeof SubmitIOCResponseSchema>;

// Query Schemas
export const IOCQuerySchema = z.object({
  q: z.string().optional(),
  type: z.enum(['ip', 'domain', 'url', 'hash']).optional(),
  verdict: z.enum(['malicious', 'suspicious', 'harmless', 'undetected', 'unknown']).optional(),
  label: z.string().optional(),
  from: z.string().optional(),
  to: z.string().optional(),
  page: z.coerce.number().default(1),
  pageSize: z.coerce.number().default(50),
  export: z.enum(['csv', 'json']).optional(),
});

export type IOCQuery = z.infer<typeof IOCQuerySchema>;
