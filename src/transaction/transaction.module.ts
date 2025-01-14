import { Module } from '@nestjs/common';
import { TransactionController } from './transaction.controller';
import { TransactionService } from './transaction.service';
import {
  Transaction,
  TransactionSchema,
} from 'src/models/transactions/schemas/transaction.schema';
import { MongooseModule } from '@nestjs/mongoose';
import {
  Account,
  AccountSchema,
} from 'src/models/accounts/schemas/account.schema';
import { MailModule } from 'src/mail/mail.module';
import { User, UserSchema } from 'src/auth/schemas/user.schema';
import { Bank, BankSchema } from 'src/models/banks/schemas/bank.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Transaction.name, schema: TransactionSchema },
      { name: Account.name, schema: AccountSchema },
      { name: User.name, schema: UserSchema },
      { name: Bank.name, schema: BankSchema },
    ]),
    MailModule,
  ],
  controllers: [TransactionController],
  providers: [TransactionService],
  exports: [TransactionService],
})
export class TransactionModule {}
