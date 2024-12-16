import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RecipientService } from './recipient.service';
import { RecipientController } from './recipient.controller';
import {
  Recipient,
  RecipientSchema,
} from '../models/recipients/schemas/recipient.schema';
import { User, UserSchema } from '../auth/schemas/user.schema';
import {
  Account,
  AccountSchema,
} from '../models/accounts/schemas/account.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Account.name, schema: AccountSchema },
      { name: Recipient.name, schema: RecipientSchema },
    ]),
  ],
  controllers: [RecipientController],
  providers: [RecipientService],
})
export class RecipientsModule {}
