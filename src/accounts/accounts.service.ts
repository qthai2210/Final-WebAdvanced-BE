import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Account, AccountDocument } from 'src/models/accounts/schemas/account.schema';
import { Model } from 'mongoose';
import { JwtUtil } from 'src/utils/jwt.util';

@Injectable()
export class AccountsService {
  constructor(
    @InjectModel(Account.name) private accountModel: Model<AccountDocument>,
    private JWTUtil: JwtUtil
  ) { }

  async createOne(accessToken: string): Promise<Account> {
    try {
      const decoded = this.JWTUtil.decodeJwt(accessToken);
      console.log(decoded);
      console.log(accessToken);
      const digits = '0123456789';
      let accountNumber = '';
      for (let i = 0; i < digits.length; i++) {
        accountNumber += digits[Math.floor(Math.random() * digits.length)];
      }
      const newPaymentAccount = new this.accountModel({
        accountNumber: accountNumber,
        userId: decoded.sub,
      })
      return (await newPaymentAccount.save()).populate(['userId'])
    } catch (error) {
      throw error;
    }
  }
}
