import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type BankDocument = Bank & Document;

@Schema({ timestamps: true })
export class Bank {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  code: string;

  @Prop({ required: true })
  publicKey: string;

  @Prop({ required: true })
  apiEndpoint: string;

  @Prop({ required: true })
  secretKey: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: 0 })
  apiUrl: string;
}

export const BankSchema = SchemaFactory.createForClass(Bank);
