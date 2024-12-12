import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { DebtController } from './debt.controller';
import { DebtService } from './debt.service';
import { Debt, DebtSchema } from '../models/debts/schemas/debt.schema';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Debt.name, schema: DebtSchema }]),
    AuthModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
    }),
  ],
  controllers: [DebtController],
  providers: [DebtService],
})
export class DebtModule {}
