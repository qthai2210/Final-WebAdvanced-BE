import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as amqp from 'amqplib';

import {
  Notification,
  NotificationDocument,
} from './schemas/notification.schema';
import { CreateNotificationDto } from './interfaces/notification.interface';
import { User } from '../auth/schemas/user.schema';

@Injectable()
export class NotificationService implements OnModuleInit {
  private connection: amqp.Connection;
  private channel: amqp.Channel;

  constructor(
    @InjectModel(Notification.name)
    private notificationModel: Model<NotificationDocument>,
    @InjectModel(User.name)
    private userModel: Model<User>,
  ) {}

  async onModuleInit() {
    await this.connectQueue();
  }

  private async connectQueue() {
    try {
      this.connection = await amqp.connect(process.env.RABBITMQ_URL);
      this.channel = await this.connection.createChannel();
      await this.channel.assertQueue(process.env.RABBITMQ_QUEUE, {
        durable: true,
      });
      console.log('RabbitMQ connected successfully');
    } catch (error) {
      console.error('RabbitMQ connection error:', error);
      // Add retry logic
      setTimeout(() => this.connectQueue(), 5000);
    }
  }

  async createNotification(
    createNotificationDto: CreateNotificationDto,
  ): Promise<Notification> {
    try {
      const notification = new this.notificationModel(createNotificationDto);
      await this.channel?.sendToQueue(
        process.env.RABBITMQ_QUEUE,
        Buffer.from(JSON.stringify(createNotificationDto)),
      );
      return await notification.save();
    } catch (error) {
      console.error('Error creating notification:', error);
      throw error;
    }
  }

  async getNotificationsByUser(userId: string): Promise<Notification[]> {
    return this.notificationModel
      .find({ userId })
      .sort({ createdAt: -1 })
      .exec();
  }

  async consumeNotifications() {
    try {
      this.channel.consume(process.env.RABBITMQ_QUEUE, (data) => {
        const notification = JSON.parse(data.content);
        console.log('Received notification:', notification);
        this.channel.ack(data);
      });
    } catch (error) {
      console.error('Error consuming notifications:', error);
    }
  }
}
