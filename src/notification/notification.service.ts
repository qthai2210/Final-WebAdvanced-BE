import { Injectable, OnModuleInit, Inject } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { INotificationGateway } from './interfaces/notification-gateway.interface';

import {
  Notification,
  NotificationDocument,
} from './schemas/notification.schema';
import { CreateNotificationDto } from './interfaces/notification.interface';
import { User } from '../auth/schemas/user.schema';

@Injectable()
export class NotificationService implements OnModuleInit {
  constructor(
    @InjectModel(Notification.name)
    private notificationModel: Model<NotificationDocument>,
    @InjectModel(User.name)
    private userModel: Model<User>,
    @Inject('INotificationGateway')
    private notificationGateway: INotificationGateway,
  ) {}

  onModuleInit() {
    // Set callback for when user connects
    (this.notificationGateway as any).setOnUserConnectedCallback(
      (userId: string) => {
        this.handleUserReconnect(userId);
      },
    );
  }

  async createNotification(
    createNotificationDto: CreateNotificationDto,
  ): Promise<Notification> {
    try {
      const notification = new this.notificationModel(createNotificationDto);
      const savedNotification = await notification.save();

      // Gửi notification ngay nếu user online
      const isUserOnline = this.notificationGateway.isUserOnline(
        createNotificationDto.userId,
      );
      if (isUserOnline) {
        this.notificationGateway.sendNotificationToUser(
          createNotificationDto.userId,
          savedNotification,
        );
      }

      return savedNotification;
    } catch (error) {
      console.error('Error creating notification:', error);
      throw error;
    }
  }

  async getUnreadNotifications(userId: string): Promise<Notification[]> {
    return this.notificationModel
      .find({
        userId,
        isRead: false,
        createdAt: {
          $gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Trong 24h
        },
      })
      .sort({ createdAt: -1 })
      .exec();
  }

  async getNotificationsByUser(userId: string): Promise<Notification[]> {
    return this.notificationModel
      .find({ userId })
      .sort({ createdAt: -1 })
      .exec();
  }

  // Xử lý khi user online trở lại
  async handleUserReconnect(userId: string) {
    try {
      // Lấy các notification chưa đọc từ database
      const unreadNotifications = await this.notificationModel
        .find({
          userId,
          isRead: false,
          createdAt: {
            $gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Trong 24h
          },
        })
        .sort({ createdAt: -1 })
        .exec();

      // Gửi lại cho user
      unreadNotifications.forEach((notification) => {
        this.notificationGateway.sendNotificationToUser(userId, notification);
      });
    } catch (error) {
      console.error('Error handling user reconnect:', error);
    }
  }
}
