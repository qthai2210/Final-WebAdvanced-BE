import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

import { Transaction } from '../../transactions/schemas/transaction.schema';
import { User } from 'src/auth/schemas/user.schema';

export type DebtDocument = Debt & Document;

@Schema({ timestamps: true })
export class Debt {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  fromUserId: User;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  toUserId: User;

  @Prop({ required: true })
  amount: number;

  @Prop()
  content: string;

  @Prop({ default: 'pending', enum: ['pending', 'paid', 'cancelled'] })
  status: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' })
  transactionId: Transaction;
}

export const DebtSchema = SchemaFactory.createForClass(Debt);
