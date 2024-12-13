export interface INotificationGateway {
  isUserOnline(userId: string): boolean;
  sendNotificationToUser(userId: string, notification: any): void;
}
