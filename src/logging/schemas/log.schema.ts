import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type LogDocument = Log & Document;

@Schema({ timestamps: true })
export class Log {
  @Prop({ required: true })
  method: string;

  @Prop({ required: true })
  url: string;

  @Prop({ required: true })
  executionTime: number;

  @Prop()
  userId?: string;

  @Prop()
  statusCode: number;

  @Prop({ type: Object })
  requestBody: Record<string, any>;

  @Prop({ type: Object })
  responseData: Record<string, any>;

  @Prop({ type: Object })
  headers: Record<string, any>;

  @Prop()
  userAgent: string;

  @Prop()
  ip: string;

  @Prop()
  error?: string;
}

export const LogSchema = SchemaFactory.createForClass(Log);
