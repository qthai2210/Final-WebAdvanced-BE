import { Controller, Get, Query, Param } from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { LoggingService } from './logging.service';

@ApiTags('logs')
@ApiBearerAuth('access-token')
@Controller('logs')
export class LoggingController {
  constructor(private readonly loggingService: LoggingService) {}

  @Get()
  async getAllLogs() {
    return this.loggingService.getLogs();
  }

  @Get('by-date')
  async getLogsByDate(
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
  ) {
    return this.loggingService.getLogsByDateRange(
      new Date(startDate),
      new Date(endDate),
    );
  }

  @Get('by-method')
  async getLogsByMethod(@Query('method') method: string) {
    return this.loggingService.getLogsByMethod(method);
  }

  @Get('errors')
  async getErrorLogs() {
    return this.loggingService.getErrorLogs();
  }

  @Get('user/:userId')
  async getLogsByUser(@Param('userId') userId: string) {
    return this.loggingService.getLogsByUserId(userId);
  }

  @Get('status/:code')
  async getLogsByStatus(@Param('code') statusCode: number) {
    return this.loggingService.getLogsByStatusCode(statusCode);
  }

  @Get('slow-requests')
  async getSlowRequests(@Query('threshold') threshold?: number) {
    return this.loggingService.getSlowRequests(threshold);
  }
}
