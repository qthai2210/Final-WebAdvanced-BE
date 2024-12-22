import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import {
  Account,
  AccountDocument,
} from 'src/models/accounts/schemas/account.schema';
import { Model } from 'mongoose';
import { JwtUtil } from 'src/utils/jwt.util';
import { Recipient } from 'src/models/recipients/schemas/recipient.schema';
import { User } from 'src/auth/schemas/user.schema';

@Injectable()
export class AccountsService {
  constructor(
    @InjectModel(Account.name) private accountModel: Model<AccountDocument>,
    @InjectModel(Recipient.name) private recipientModel: Model<Recipient>,
    @InjectModel(User.name) private userModel: Model<User>,
    private JWTUtil: JwtUtil,
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
      });
      return (await newPaymentAccount.save()).populate(['userId']);
    } catch (error) {
      throw error;
    }
  }

  async getUserAccounts(accessToken: string): Promise<Account> {
    const data = await this.JWTUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    const account = await this.accountModel
      .findOne({ userId: data.sub })
      .exec();

    if (!account) {
      throw new NotFoundException(
        `No accounts found for user with ID ${data.sub}`,
      );
    }

    return account;
  }

  async getAccountByAccountNumber(
    accessToken: string,
    accountNumber: string,
  ): Promise<any> {
    const data = await this.JWTUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    const account = await this.accountModel
      .findOne({ accountNumber: accountNumber })
      .exec();

    if (!account) {
      throw new NotFoundException('Account not found');
    }

    const recipient = await this.recipientModel.findOne({
      accountNumber: accountNumber,
      userId: data.sub,
    });

    if (recipient) {
      return {
        accountNumber: account.accountNumber,
        nickname: recipient.nickname,
      };
    } else {
      const user = await this.userModel.findById(account.userId);
      return {
        accountNumber: account.accountNumber,
        nickname: user.username,
      };
    }
  }

  async getAccountDetail(
    accountNumber?: string,
    username?: string,
  ): Promise<any> {
    let account: any;

    if (accountNumber) {
      account = await this.accountModel
        .findOne({ accountNumber: accountNumber })
        .exec();
    } else {
      const user = await this.userModel.findOne({ username: username }).exec();

      account = await this.accountModel.findOne({ userId: user.id }).exec();
    }

    if (!account) {
      throw new NotFoundException('Account not found');
    }

    return account;
  }
}
