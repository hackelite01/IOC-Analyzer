import { Schema, Document, model, models } from 'mongoose';
import { IOCType, VTNormalized } from '../validators';

export interface IIOC extends Document {
  ioc: string;
  type: IOCType;
  label?: string;
  vt: {
    raw: Record<string, unknown>;
    normalized: VTNormalized;
  };
  fetchedAt: Date;
  updatedAt: Date;
  cacheTtlSec: number;
  meta?: {
    createdBy?: string;
    caseId?: string;
  };
}

const VTProviderSchema = new Schema({
  engine: { type: String, required: true },
  category: { type: String, required: true },
  result: { type: String },
}, { _id: false });

const VTStatsSchema = new Schema({
  malicious: { type: Number, default: 0 },
  suspicious: { type: Number, default: 0 },
  harmless: { type: Number, default: 0 },
  undetected: { type: Number, default: 0 },
  timeout: { type: Number },
}, { _id: false });

const VTNormalizedSchema = new Schema({
  verdict: {
    type: String,
    enum: ['malicious', 'suspicious', 'harmless', 'undetected', 'unknown'],
    required: true,
  },
  stats: { type: VTStatsSchema, required: true },
  reputation: { type: Number },
  categories: [{ type: String }],
  tags: [{ type: String }],
  last_analysis_date: { type: String },
  providers: [VTProviderSchema],
}, { _id: false });

const VTSchema = new Schema({
  raw: { type: Schema.Types.Mixed, required: true },
  normalized: { type: VTNormalizedSchema, required: true },
}, { _id: false });

const IOCSchema = new Schema<IIOC>({
  ioc: { 
    type: String, 
    required: true,
    index: true,
  },
  type: {
    type: String,
    enum: ['ip', 'domain', 'url', 'hash'],
    required: true,
    index: true,
  },
  label: { 
    type: String,
    index: true,
  },
  vt: { 
    type: VTSchema, 
    required: true 
  },
  fetchedAt: { 
    type: Date, 
    default: Date.now,
    index: true,
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  },
  cacheTtlSec: { 
    type: Number, 
    default: 86400 // 24 hours
  },
  meta: {
    createdBy: { type: String },
    caseId: { type: String, index: true },
  },
}, {
  timestamps: { updatedAt: 'updatedAt' },
});

// Compound index for efficient lookups
IOCSchema.index({ ioc: 1, type: 1 }, { unique: true });
IOCSchema.index({ 'vt.normalized.verdict': 1 });
IOCSchema.index({ fetchedAt: -1 });

export const IOC = models.IOC || model<IIOC>('IOC', IOCSchema);
