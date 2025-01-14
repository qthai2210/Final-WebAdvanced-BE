import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtStrategy } from './jwt.strategy';
import { AuthController } from './auth.controller';
import { User, UserSchema } from './schemas/user.schema';
import { ConfigService } from '@nestjs/config';
import { MailModule } from 'src/mail/mail.module';
import { AccountsModule } from 'src/accounts/accounts.module';
import { AdminEmployeeController } from './admin/admin-employee.controller';
import { LoggingModule } from '../logging/logging.module';
import { LoggingInterceptor } from '../logging/logging.interceptor';
import { TransactionModule } from 'src/transaction/transaction.module';
import {
  Transaction,
  TransactionSchema,
} from 'src/models/transactions/schemas/transaction.schema';

@Module({
  imports: [
    MailModule,
    PassportModule,
    AccountsModule,
    TransactionModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '120m' },
      }),
      inject: [ConfigService],
    }),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Transaction.name, schema: TransactionSchema },
    ]),
    LoggingModule,
  ],
  providers: [
    AuthService,
    JwtStrategy,
    {
      provide: 'LOGGING_INTERCEPTOR',
      useClass: LoggingInterceptor,
    },
  ],
  controllers: [AuthController, AdminEmployeeController],
  exports: [AuthService],
})
export class AuthModule {}
