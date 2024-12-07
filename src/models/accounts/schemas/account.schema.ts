import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from 'src/auth/schemas/user.schema';

export type AccountDocument = Account & Document;

@Schema({ timestamps: true })
export class Account {
  @Prop({ required: true, unique: true })
  accountNumber: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  userId: User;

  @Prop({ default: 0 })
  balance: number;

  @Prop({ default: 'payment' })
  type: string;

  @Prop({ default: true })
  isActive: boolean;
}

export const AccountSchema = SchemaFactory.createForClass(Account);
