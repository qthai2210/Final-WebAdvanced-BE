import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ClientsModule, Transport } from '@nestjs/microservices';

import { NotificationService } from './notification.service';
import {
  Notification,
  NotificationSchema,
} from './schemas/notification.schema';
import { AuthModule } from '../auth/auth.module'; // Add this
import { UserSchema } from 'src/auth/schemas/user.schema';
import { NotificationGateway } from './notification.gateway';
import { NotificationController } from './notification.controller';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Notification.name, schema: NotificationSchema },
      { name: 'User', schema: UserSchema },
    ]),
    AuthModule, // Import AuthModule instead of directly importing User schema
    ClientsModule.register([
      {
        name: 'NOTIFICATION_SERVICE',
        transport: Transport.RMQ,
        options: {
          urls: [process.env.RABBITMQ_URL],
          queue: process.env.RABBITMQ_QUEUE,
          queueOptions: {
            durable: true,
          },
          noAssert: false,
          persistent: true,
        },
      },
    ]),
  ],
  providers: [
    NotificationGateway,
    {
      provide: 'INotificationGateway',
      useClass: NotificationGateway,
    },
    NotificationService,
  ],
  controllers: [NotificationController],
  exports: [NotificationService],
})
export class NotificationModule {}
