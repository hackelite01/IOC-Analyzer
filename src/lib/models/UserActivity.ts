import mongoose, { Schema, Document } from 'mongoose';

export interface IUserActivity extends Document {
  _id: string;
  userId: mongoose.Types.ObjectId;
  action: string;
  details?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}

const UserActivitySchema = new Schema<IUserActivity>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
    },
    action: {
      type: String,
      required: [true, 'Action is required'],
      trim: true,
      maxlength: [100, 'Action cannot exceed 100 characters'],
    },
    details: {
      type: Schema.Types.Mixed,
      default: {},
    },
    ipAddress: {
      type: String,
      trim: true,
    },
    userAgent: {
      type: String,
      trim: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: false, // We use our own timestamp field
  }
);

// Indexes for performance
UserActivitySchema.index({ userId: 1, timestamp: -1 });
UserActivitySchema.index({ timestamp: -1 });
UserActivitySchema.index({ action: 1 });

export const UserActivity = mongoose.models.UserActivity || mongoose.model<IUserActivity>('UserActivity', UserActivitySchema);
