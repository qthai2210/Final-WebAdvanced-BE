import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { Bank } from '../../banks/schemas/bank.schema';

export type TransactionDocument = Transaction & Document;

@Schema({ timestamps: true })
export class Transaction {
  @Prop({ required: true })
  fromAccount: string;

  @Prop({ required: true })
  toAccount: string;

  @Prop({ required: true })
  amount: number;

  @Prop({
    required: true,
    enum: ['internal_transfer', 'external_transfer', 'debt_payment', 'deposit'],
  })
  type: string;

  @Prop({ default: 'pending', enum: ['pending', 'completed', 'failed'] })
  status: string;

  @Prop({ default: 0 })
  fee: number;

  @Prop({ enum: ['sender', 'receiver'] })
  feeType: string;

  @Prop()
  content: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Bank' })
  bankId: Bank;

  @Prop()
  otp: string;

  @Prop()
  otpExpired: Date;

  @Prop()
  signature: string;
}

export const TransactionSchema = SchemaFactory.createForClass(Transaction);
