import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum UserRole {
  CUSTOMER = 'customer',
  EMPLOYEE = 'employee',
  ADMIN = 'admin',
}

export enum UserStatus {
  ACTIVE = 'active',
  LOCKED = 'locked',
  PENDING = 'pending',
}

export type UserDocument = User & Document;

@Schema({
  timestamps: true,
  collection: 'users',
  toJSON: {
    virtuals: true,
    transform: function (doc, ret) {
      ret.id = ret._id;
      delete ret.__v;
      return ret;
    },
  },
})
export class User {
  @Prop({ required: true, unique: true })
  username: string;

  @Prop({ required: true })
  password: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  phone: string;

  @Prop({ required: true })
  fullName: string;

  @Prop({
    type: String,
    enum: UserRole,
    default: UserRole.CUSTOMER,
  })
  role: UserRole;

  @Prop({
    type: String,
    enum: UserStatus,
    default: UserStatus.PENDING,
  })
  status: UserStatus;

  @Prop()
  identityNumber: string;

  @Prop()
  dateOfBirth: Date;

  @Prop()
  address: string;

  @Prop()
  lastLoginAt: Date;

  @Prop()
  refreshToken: string;

  @Prop()
  resetPasswordToken: string;

  @Prop()
  resetPasswordExpires: Date;

  @Prop({ default: 0 })
  failedLoginAttempts: number;

  @Prop()
  lockUntil: Date;

  @Prop()
  resetPasswordOTP?: string;

  @Prop()
  resetPasswordOTPExpires?: Date;

  isLocked(): boolean {
    return !!(this.lockUntil && this.lockUntil > new Date());
  }
}

const UserSchema = SchemaFactory.createForClass(User);

UserSchema.set('toObject', { virtuals: true });
UserSchema.set('toJSON', { virtuals: true });

// Add indexes
UserSchema.index({ email: 1 });
UserSchema.index({ phone: 1 });
UserSchema.index({ username: 1 });
UserSchema.index({ identityNumber: 1 });

// Add methods to schema
UserSchema.methods.isLocked = function (): boolean {
  return !!(this.lockUntil && this.lockUntil > new Date());
};

// Add hooks
UserSchema.pre('save', function (next) {
  if (this.isModified('failedLoginAttempts') && this.failedLoginAttempts >= 5) {
    // Lock account for 15 minutes
    this.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
  }
  next();
});

export { UserSchema };
