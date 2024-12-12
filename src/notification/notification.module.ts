import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { NotificationService } from './notification.service';
import {
  Notification,
  NotificationSchema,
} from './schemas/notification.schema';
import { AuthModule } from '../auth/auth.module'; // Add this
import { UserSchema } from 'src/auth/schemas/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Notification.name, schema: NotificationSchema },
      { name: 'User', schema: UserSchema },
    ]),
    AuthModule, // Import AuthModule instead of directly importing User schema
  ],
  providers: [NotificationService],
  exports: [NotificationService],
})
export class NotificationModule {}
