import { Injectable } from '@nestjs/common';
import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { INotificationGateway } from './interfaces/notification-gateway.interface';

@Injectable()
@WebSocketGateway({
  cors: {
    origin: '*',
  },
})
export class NotificationGateway
  implements OnGatewayConnection, OnGatewayDisconnect, INotificationGateway
{
  @WebSocketServer()
  server: Server;

  private userSockets = new Map<string, string>();
  private onUserConnectedCallback: (userId: string) => void;

  setOnUserConnectedCallback(callback: (userId: string) => void) {
    this.onUserConnectedCallback = callback;
  }

  handleConnection(client: Socket) {
    const userId = client.handshake.query.userId as string;
    console.log(client.handshake);
    if (userId) {
      this.userSockets.set(userId, client.id);
      console.log(`Client connected: ${userId}`);

      if (this.onUserConnectedCallback) {
        this.onUserConnectedCallback(userId);
      }
    }
  }

  handleDisconnect(client: Socket) {
    const userId = [...this.userSockets.entries()].find(
      ([_, socketId]) => socketId === client.id,
    )?.[0];
    if (userId) {
      this.userSockets.delete(userId);
      console.log(`Client disconnected: ${userId}`);
    }
  }

  sendNotificationToUser(userId: string, notification: any) {
    const socketId = this.userSockets.get(userId);
    if (socketId) {
      this.server.to(socketId).emit('newNotification', {
        ...notification,
        isRead: false,
      });
    }
  }

  isUserOnline(userId: string): boolean {
    return this.userSockets.has(userId);
  }

  broadcastNotificationUpdate(
    userId: string,
    notificationId: string,
    isRead: boolean,
  ) {
    try {
      const socketId = this.userSockets.get(userId);
      if (socketId) {
        this.server.to(socketId).emit('notificationUpdate', {
          id: notificationId,
          isRead,
          updatedAt: new Date().toISOString(),
        });
        return true;
      }
      return false;
    } catch (error) {
      console.error('Failed to broadcast notification update:', error);
      return false;
    }
  }
}
