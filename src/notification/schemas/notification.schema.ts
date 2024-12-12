import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';

export type NotificationDocument = Notification & Document;

@Schema({ timestamps: true })
export class Notification {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  userId: User;

  @Prop({ required: true })
  content: string;

  @Prop({ required: true })
  type: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, refPath: 'type' })
  relatedId: mongoose.Types.ObjectId;

  @Prop({ default: false })
  isRead: boolean;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);
