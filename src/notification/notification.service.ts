import {
  Injectable,
  OnModuleInit,
  Inject,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { INotificationGateway } from './interfaces/notification-gateway.interface';
import {
  Notification,
  NotificationDocument,
} from './schemas/notification.schema';
import { CreateNotificationDto } from './interfaces/notification.interface';
import { JwtUtil } from '../utils/jwt.util';
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
    private readonly jwtUtil: JwtUtil,
  ) {}

  onModuleInit() {
    // Set callback for when user connects
    (this.notificationGateway as any).setOnUserConnectedCallback(
      (userId: string) => {
        console.log('User connected:', userId);
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
      console.log('Notification created:', savedNotification);
      // Gửi notification ngay nếu user online
      const isUserOnline = this.notificationGateway.isUserOnline(
        createNotificationDto.userId,
      );
      if (isUserOnline) {
        console.log('User online, sending notification');
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

  async getNotificationsByUser(accessToken: string): Promise<Notification[]> {
    const user = this.decodeToken(accessToken);
    return this.notificationModel
      .find({ userId: user.sub })
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

  private decodeToken(accessToken: string) {
    try {
      const decoded = this.jwtUtil.decodeJwt(accessToken);
      if (!decoded.sub) {
        throw new UnauthorizedException('Invalid token');
      }
      return decoded;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async markAsRead(notificationId: string, accessToken: string) {
    try {
      const user = this.decodeToken(accessToken);
      const notification = await this.notificationModel.findOne({
        _id: notificationId,
        userId: user.sub,
      });

      if (!notification) {
        throw new NotFoundException('Notification not found');
      }

      notification.isRead = true;
      const savedNotification = await notification.save();

      try {
        // Attempt to broadcast the update, but don't fail if it doesn't work
        if (this.notificationGateway.isUserOnline(user.sub)) {
          this.notificationGateway.broadcastNotificationUpdate(
            user.sub,
            notificationId,
            true,
          );
        }
      } catch (error) {
        console.error('Failed to broadcast notification update:', error);
        // Continue execution even if broadcast fails
      }

      return savedNotification;
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new Error('Failed to mark notification as read');
    }
  }

  async markAllAsRead(accessToken: string) {
    const user = this.decodeToken(accessToken);
    const result = await this.notificationModel.updateMany(
      { userId: user.sub, isRead: false },
      { $set: { isRead: true } },
    );

    return { updated: result.modifiedCount };
  }

  async getUnreadCount(accessToken: string) {
    const user = this.decodeToken(accessToken);
    const count = await this.notificationModel.countDocuments({
      userId: user.sub,
      isRead: false,
    });
    return { count };
  }
}
