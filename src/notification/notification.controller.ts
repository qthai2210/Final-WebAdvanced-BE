import { Controller, Patch, Param, Post, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { NotificationService } from './notification.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { BearerToken } from '../auth/decorators/auth.decorator';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../auth/schemas/user.schema';

@ApiTags('notifications')
@ApiBearerAuth('access-token')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.CUSTOMER)
@Controller('notifications')
export class NotificationController {
  constructor(private readonly notificationService: NotificationService) {}

  @Patch(':id/read')
  @ApiOperation({ summary: 'Mark a notification as read' })
  async markAsRead(
    @BearerToken() accessToken: string,
    @Param('id') id: string,
  ) {
    return this.notificationService.markAsRead(id, accessToken);
  }

  @Post('mark-all-read')
  @ApiOperation({ summary: 'Mark all notifications as read' })
  async markAllAsRead(@BearerToken() accessToken: string) {
    return this.notificationService.markAllAsRead(accessToken);
  }

  @Get('unread-count')
  @ApiOperation({ summary: 'Get count of unread notifications' })
  async getUnreadCount(@BearerToken() accessToken: string) {
    return this.notificationService.getUnreadCount(accessToken);
  }

  @Get()
  @ApiOperation({ summary: 'Get all notifications for current user' })
  async getAllNotifications(@BearerToken() accessToken: string) {
    return this.notificationService.getNotificationsByUser(accessToken);
  }
}
