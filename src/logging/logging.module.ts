import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { LoggingInterceptor } from './logging.interceptor';
import { LoggingService } from './logging.service';
import { LoggingController } from './logging.controller';
import { Log, LogSchema } from './schemas/log.schema';

@Module({
  imports: [MongooseModule.forFeature([{ name: Log.name, schema: LogSchema }])],
  providers: [LoggingService, LoggingInterceptor],
  exports: [LoggingService, LoggingInterceptor], // Make sure both are exported
  controllers: [LoggingController],
})
export class LoggingModule {}
