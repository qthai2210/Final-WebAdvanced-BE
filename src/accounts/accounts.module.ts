import { Module } from '@nestjs/common';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { Mongoose } from 'mongoose';
import { MongooseModule } from '@nestjs/mongoose';
import { Account, AccountSchema } from 'src/models/accounts/schemas/account.schema';

@Module({
  imports: [MongooseModule.forFeature([
    { name: Account.name, schema: AccountSchema }
  ])],
  controllers: [AccountsController],
  providers: [AccountsService],
  exports: [AccountsService]
})
export class AccountsModule { }
