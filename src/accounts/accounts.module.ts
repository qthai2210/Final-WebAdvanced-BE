import { Module } from '@nestjs/common';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  Account,
  AccountSchema,
} from 'src/models/accounts/schemas/account.schema';
import { User, UserSchema } from 'src/auth/schemas/user.schema';
import {
  Recipient,
  RecipientSchema,
} from 'src/models/recipients/schemas/recipient.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Account.name, schema: AccountSchema }]),
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    MongooseModule.forFeature([
      { name: Recipient.name, schema: RecipientSchema },
    ]),
  ],
  controllers: [AccountsController],
  providers: [AccountsService],
  exports: [AccountsService],
})
export class AccountsModule {}
