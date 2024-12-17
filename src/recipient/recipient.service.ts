import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtUtil } from '../utils/jwt.util';
import {
  Recipient,
  RecipientDocument,
} from '../models/recipients/schemas/recipient.schema';
import { User, UserDocument } from '../auth/schemas/user.schema';
import {
  Account,
  AccountDocument,
} from '../models/accounts/schemas/account.schema';
import { RecipientDto } from './recipient.dto';

@Injectable()
export class RecipientService {
  constructor(
    private jwtUtil: JwtUtil,
    @InjectModel(Recipient.name)
    private recipientModel: Model<RecipientDocument>,
    @InjectModel(User.name)
    private userModel: Model<UserDocument>,
    @InjectModel(Account.name)
    private accountModel: Model<AccountDocument>,
  ) {}

  async addRecipient(
    accessToken: string,
    recipientDto: RecipientDto,
  ): Promise<Recipient> {
    console.log(accessToken);
    const data = await this.jwtUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    const account = await this.accountModel
      .findOne({ accountNumber: recipientDto.accountNumber })
      .exec();
    if (!account) {
      throw new NotFoundException('Payment account not found');
    }

    if (!recipientDto.nickname || recipientDto.nickname.length === 0) {
      const user = await this.userModel.findById(account.userId).exec();
      recipientDto.nickname = user.username;
    }

    const existedRecipient = await this.recipientModel.findOne({
      userId: data.sub,
      accountNumber: recipientDto.accountNumber,
    });
    if (existedRecipient) {
      throw new HttpException(
        'Recipient already exists for this user',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    const recipient = new this.recipientModel({
      userId: data.sub,
      ...recipientDto,
    });

    return recipient.save();
  }

  async getRecipients(accessToken: string): Promise<Recipient[]> {
    const data = await this.jwtUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    return this.recipientModel.find({ userId: data.sub }).exec();
  }

  async updateRecipient(
    accessToken: string,
    recipientDto: RecipientDto,
  ): Promise<Recipient> {
    const data = await this.jwtUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    const recipient = await this.recipientModel
      .findOne({ userId: data.sub, accountNumber: recipientDto.accountNumber })
      .exec();
    if (!recipient) {
      throw new NotFoundException('Recipient not found');
    }

    recipient.nickname = recipientDto.nickname;
    return recipient.save();
  }

  async removeRecipient(
    accessToken: string,
    accountNumber: string,
  ): Promise<Recipient> {
    const data = await this.jwtUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    const recipient = await this.recipientModel.findOne({
      userId: data.sub,
      accountNumber,
    });
    const result = await this.recipientModel
      .deleteOne({ userId: data.sub, accountNumber })
      .exec();

    if (result.deletedCount === 0) {
      throw new NotFoundException('Recipient not found');
    }

    return recipient;
  }
}
