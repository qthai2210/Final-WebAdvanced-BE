import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../../auth/schemas/user.schema';
import { Bank } from '../../banks/schemas/bank.schema';

export type RecipientDocument = Recipient & Document;

@Schema({ timestamps: true })
export class Recipient {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  userId: User;

  @Prop({ required: true })
  accountNumber: string;

  @Prop()
  nickname: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Bank' })
  bankId: Bank;

  @Prop({ default: true })
  isInternal: boolean;
}

export const RecipientSchema = SchemaFactory.createForClass(Recipient);
