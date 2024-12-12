import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from './app.controller';
import { AppService } from './app.service';

import { validationSchema } from './config/validation.schema';
import { AuthModule } from './auth/auth.module';
import { DebtModule } from './debt/debt.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema,
      //load: [configuration],
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGO_DATABASE_URI'),
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    DebtModule,
    // AccountsModule,
    // TransactionsModule,
    // DebtsModule,
    // BanksModule,
    // RecipientsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
