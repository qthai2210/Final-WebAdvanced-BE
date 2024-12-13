import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ClientsModule, Transport } from '@nestjs/microservices';

import { validationSchema } from './config/validation.schema';
import { AuthModule } from './auth/auth.module';
import { DebtModule } from './debt/debt.module';
import { NotificationModule } from './notification/notification.module';
import { MailModule } from './mail/mail.module';
import { UtilsModule } from './utils/utils.module';
import { TransactionModule } from './transaction/transaction.module';
import { AccountsModule } from './accounts/accounts.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema,
    }),
    ClientsModule.registerAsync([
      {
        name: 'RABBIT_MQ_MODULE',
        imports: [ConfigModule],
        useFactory: async (configService: ConfigService) => ({
          transport: Transport.RMQ,
          options: {
            urls: [configService.get<string>('RABBITMQ_URL')],
            queue: configService.get<string>('RABBITMQ_QUEUE'),
            queueOptions: {
              durable: false,
            },
          },
        }),
        inject: [ConfigService],
      },
    ]),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGO_DATABASE_URI'),
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    DebtModule,
    NotificationModule,
    MailModule,
    UtilsModule,
    TransactionModule,
    AccountsModule,

    // AccountsModule,
    // TransactionsModule,
    // DebtsModule,
    // BanksModule,
    // RecipientsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
