export interface CreateNotificationDto {
  userId: string;
  content: string;
  type: string;
  relatedId?: string;
}
