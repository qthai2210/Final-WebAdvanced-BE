import { Module } from '@nestjs/common';
import { EmployeeController } from './employee.controller';
import { EmployeeService } from './employee.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  Transaction,
  TransactionSchema,
} from 'src/models/transactions/schemas/transaction.schema';
import { AccountsModule } from 'src/accounts/accounts.module';
import { User, UserSchema } from 'src/auth/schemas/user.schema';
import {
  Account,
  AccountSchema,
} from 'src/models/accounts/schemas/account.schema';
import {
  Recipient,
  RecipientSchema,
} from 'src/models/recipients/schemas/recipient.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Transaction.name, schema: TransactionSchema },
      { name: User.name, schema: UserSchema },
      { name: Account.name, schema: AccountSchema },
      { name: Recipient.name, schema: RecipientSchema },
    ]),
    AccountsModule,
  ],
  controllers: [EmployeeController],
  providers: [EmployeeService],
})
export class EmployeeModule { }
