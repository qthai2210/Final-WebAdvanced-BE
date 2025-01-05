import { Module } from '@nestjs/common';
import { ExternalController } from './external.controller';
import { ExternalService } from './external.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  Transaction,
  TransactionSchema,
} from 'src/models/transactions/schemas/transaction.schema';
import {
  Account,
  AccountSchema,
} from 'src/models/accounts/schemas/account.schema';
import { User, UserSchema } from 'src/auth/schemas/user.schema';
import { Bank, BankSchema } from 'src/models/banks/schemas/bank.schema';
import { MailModule } from 'src/mail/mail.module';
import { CryptoUtil } from '../utils/crypto.util';
import { VerifyBankSignatureGuard } from './guards/verify-bank-signature.guard';
import { VerifyBankHashGuard } from './guards/verify-bank-hash.guard';

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
  controllers: [ExternalController],
  providers: [
    ExternalService,
    CryptoUtil,
    VerifyBankSignatureGuard,
    VerifyBankHashGuard,
  ],
})
export class ExternalModule {}
