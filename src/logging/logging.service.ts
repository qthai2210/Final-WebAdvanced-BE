import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Log, LogDocument } from './schemas/log.schema';

@Injectable()
export class LoggingService {
  constructor(@InjectModel(Log.name) private logModel: Model<LogDocument>) {}

  async createLog(logData: Partial<Log>): Promise<Log> {
    const log = new this.logModel(logData);
    return log.save();
  }

  async getLogs(filter: any = {}) {
    return this.logModel.find(filter).sort({ createdAt: -1 }).exec();
  }

  async getLogsByDateRange(startDate: Date, endDate: Date) {
    return this.logModel
      .find({
        createdAt: {
          $gte: startDate,
          $lte: endDate,
        },
      })
      .sort({ createdAt: -1 })
      .exec();
  }

  async getLogsByMethod(method: string) {
    return this.logModel.find({ method: method.toUpperCase() }).exec();
  }

  async getErrorLogs() {
    return this.logModel
      .find({ error: { $exists: true } })
      .sort({ createdAt: -1 })
      .exec();
  }

  async getLogsByUserId(userId: string) {
    return this.logModel.find({ userId }).sort({ createdAt: -1 }).exec();
  }

  async getLogsByStatusCode(statusCode: number) {
    return this.logModel.find({ statusCode }).sort({ createdAt: -1 }).exec();
  }

  async getSlowRequests(threshold: number = 1000) {
    return this.logModel
      .find({ executionTime: { $gt: threshold } })
      .sort({ executionTime: -1 })
      .exec();
  }
}
