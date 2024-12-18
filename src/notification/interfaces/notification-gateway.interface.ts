export interface INotificationGateway {
  sendNotificationToUser(userId: string, notification: any): void;
  isUserOnline(userId: string): boolean;
  broadcastNotificationUpdate(
    userId: string,
    notificationId: string,
    isRead: boolean,
  ): void;
}
