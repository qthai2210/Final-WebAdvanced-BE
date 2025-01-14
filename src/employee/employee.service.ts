import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Transaction } from 'src/models/transactions/schemas/transaction.schema';
import { TransactionHistoryQueryDto } from 'src/transaction/dto/transaction-history.dto';
import { DepositMoneyCreateDto } from './dto/deposit-money-create.dto';
import { Account } from 'src/models/accounts/schemas/account.schema';
import { AccountsService } from 'src/accounts/accounts.service';
import { User } from 'src/auth/schemas/user.schema';
import { JwtUtil } from 'src/utils/jwt.util';
import { Recipient } from 'src/models/recipients/schemas/recipient.schema';

@Injectable()
export class EmployeeService {
  constructor(
    @InjectModel(Transaction.name) private transactionModel: Model<Transaction>,
    @InjectModel(Account.name) private accountModel: Model<Account>,
    @InjectModel(Recipient.name) private recipientModel: Model<Recipient>,
    @InjectModel(User.name) private userModel: Model<User>,
    private JWTUtil: JwtUtil,
    private readonly accountsService: AccountsService,
  ) {}

  async getTransactionHistory(query: TransactionHistoryQueryDto): Promise<any> {
    const {
      accountNumber,
      type = 'all',
      page = 1,
      limit = 10,
      fromDate,
      toDate,
    } = query;

    // Convert page và limit sang number
    const pageNum = parseInt(page.toString(), 10);
    const limitNum = parseInt(limit.toString(), 10);

    const matchQuery: any = {
      status: 'completed',
      $or: [{ fromAccount: accountNumber }, { toAccount: accountNumber }],
    };

    if (type !== 'all') {
      switch (type) {
        case 'received':
          matchQuery.toAccount = accountNumber;
          break;
        case 'sent':
          matchQuery.fromAccount = accountNumber;
          matchQuery.type = 'internal_transfer';
          break;
        case 'debt_payment':
          matchQuery.type = 'debt_payment';
          break;
      }
    }

    if (fromDate && toDate) {
      matchQuery.createdAt = {
        $gte: new Date(fromDate),
        $lte: new Date(toDate),
      };
    }

    const totalDocuments =
      await this.transactionModel.countDocuments(matchQuery);
    const totalPages = Math.ceil(totalDocuments / limitNum);

    const transaction = await this.transactionModel
      .aggregate([
        { $match: matchQuery },
        { $sort: { createdAt: -1 } },
        { $skip: (pageNum - 1) * limitNum }, // Sử dụng giá trị đã convert
        { $limit: limitNum }, // Sử dụng giá trị đã convert
        {
          $lookup: {
            from: 'banks',
            localField: 'bankId',
            foreignField: '_id',
            as: 'bank',
          },
        },
        {
          $lookup: {
            from: 'accounts',
            localField: 'fromAccount',
            foreignField: 'accountNumber',
            as: 'FromAccountObject',
          },
        },
        {
          $unwind: {
            path: '$FromAccountObject',
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: 'FromAccountObject.userId',
            foreignField: '_id',
            as: 'fromUser',
          },
        },
        {
          $lookup: {
            from: 'accounts',
            localField: 'toAccount',
            foreignField: 'accountNumber',
            as: 'ToAccountObject',
          },
        },
        {
          $unwind: {
            path: '$ToAccountObject',
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: 'ToAccountObject.userId',
            foreignField: '_id',
            as: 'toUser',
          },
        },
        {
          $project: {
            id: '$_id',
            type: 1,
            amount: 1,
            fromAccount: 1,
            toAccount: 1,
            content: 1,
            fee: 1,
            status: 1,
            createdAt: 1,
            bankId: 1,
            'bank.name': 1,
            'fromUser.fullName': { $arrayElemAt: ['$fromUser.fullName', 0] },
            'fromUser.email': { $arrayElemAt: ['$fromUser.email', 0] },
            'toUser.fullName': { $arrayElemAt: ['$toUser.fullName', 0] },
            'toUser.email': { $arrayElemAt: ['$toUser.email', 0] },
            direction: {
              $cond: {
                if: { $eq: ['$toAccount', accountNumber] },
                then: 'in',
                else: 'out',
              },
            },
          },
        },
      ])
      .exec();

    return {
      transaction,
      totalPages,
    };
  }

  async depositMoneyIntoCustomerAccount(
    data: DepositMoneyCreateDto,
  ): Promise<any> {
    const userAccount = await this.accountsService.getAccountDetail(
      data.accountNumber,
      data.username,
    );
    if (userAccount) {
      userAccount.balance += data.amount;
      await userAccount.save();
      return true;
    } else {
      throw new NotFoundException('Account not found');
    }
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
        isRecipient: true,
      };
    } else {
      const user = await this.userModel.findById(account.userId);
      return {
        accountNumber: account?.accountNumber,
        nickname: user?.username,
        isRecipient: false,
      };
    }
  }

  async getAccountByUsername(
    accessToken: string,
    username: string,
  ): Promise<any> {
    const data = await this.JWTUtil.decodeJwt(accessToken);
    if (!data) {
      throw new UnauthorizedException('Unauthorized - User is not logged in');
    }

    const user = await this.userModel.findOne({ username: username }).exec();

    console.log('User: ' + user);

    if (!user) {
      throw new NotFoundException('Account not found');
    }

    const recipient = await this.recipientModel.findOne({
      nickname: username,
      userId: data.sub,
    });

    console.log('Recipient: ' + recipient);

    if (recipient) {
      return {
        username: user.username,
        isRecipient: true,
      };
    } else {
      const account = await this.accountModel.findOne({ userId: user._id });
      console.log('Account: ' + account);
      return {
        accountNumber: account?.accountNumber,
        nickname: user?.username,
        isRecipient: false,
      };
    }
  }
}
