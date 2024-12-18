import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Transaction } from '../models/transactions/schemas/transaction.schema';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from './dto/transaction-history.dto';
import { InternalTransferDto } from './dto/transaction-create.dto';
import { Account } from 'src/models/accounts/schemas/account.schema';
import { MailService } from 'src/mail/mail.service';
import { JwtUtil } from 'src/utils/jwt.util';
import { VerifyOtpTransactionDto } from './dto/verify-otp.dto';
import { User } from 'src/auth/schemas/user.schema';

@Injectable()
export class TransactionService {
  constructor(
    @InjectModel(Transaction.name) private transactionModel: Model<Transaction>,
    @InjectModel(Account.name) private accountModel: Model<Account>,
    @InjectModel(User.name) private userModel: Model<User>,
    private mailService: MailService,
    private JWTUtil: JwtUtil,
  ) {}

  async getTransactionHistory(
    query: TransactionHistoryQueryDto,
  ): Promise<TransactionHistoryResponseDto[]> {
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

    return this.transactionModel
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
  }

  async initiateInternalTransfer(
    accessToken: string,
    internalTransferDto: InternalTransferDto,
  ): Promise<Transaction> {
    const decoded = this.JWTUtil.decodeJwt(accessToken);

    if (!decoded) {
      throw new UnauthorizedException('Invalid access token');
    }

    const fromAccount = await this.accountModel.findOne({
      userId: decoded.sub,
    });
    console.log(fromAccount);
    const { toAccount, amount, content, feeType } = internalTransferDto;

    const receiverAccount = await this.accountModel.findOne({
      accountNumber: toAccount,
    });

    if (!fromAccount || !receiverAccount) {
      throw new NotFoundException('Account not found');
    }

    if (fromAccount.balance < amount) {
      throw new BadRequestException('Insufficient balance');
    }

    const fee = amount / 100; // Example fee
    const totalAmount = feeType === 'sender' ? amount + fee : amount;

    if (fromAccount.balance < totalAmount) {
      throw new BadRequestException('Insufficient balance to cover the fee');
    }

    const transaction = new this.transactionModel({
      fromAccount: fromAccount.accountNumber.toString(),
      toAccount: toAccount,
      amount: amount,
      content: content,
      fee: fee,
      feeType: feeType,
      status: 'pending',
      type: 'internal_transfer',
    });

    await transaction.save();
    const senderUser = await this.userModel.findById(fromAccount.userId);
    console.log(senderUser);
    // Send OTP to the sender's email
    await this.mailService.sendOtpToVerifyTransaction(
      senderUser.email,
      transaction._id.toString(),
    );

    return transaction;
  }

  async verifyOtp(verifyOtpDto: VerifyOtpTransactionDto): Promise<Transaction> {
    const { otp, transactionId } = verifyOtpDto;

    const transaction = await this.transactionModel.findById(transactionId);
    if (!transaction) {
      throw new NotFoundException('Transaction not found');
    }

    console.log(transaction);
    const senderAccount = await this.accountModel.findOne({
      accountNumber: transaction.fromAccount,
    });
    if (!senderAccount) {
      throw new NotFoundException('Sender account not found');
    }

    const isValidOtp = await this.mailService.verifyOtpTransaction(
      transactionId,
      otp,
    );
    if (!isValidOtp) {
      throw new UnauthorizedException('Invalid OTP');
    }

    const receiverAccount = await this.accountModel.findOne({
      accountNumber: transaction.toAccount,
    });
    if (!receiverAccount) {
      throw new NotFoundException('Receiver account not found');
    }

    if (transaction.feeType === 'sender') {
      senderAccount.balance -= transaction.amount + transaction.fee;
      receiverAccount.balance += transaction.amount;
    } else {
      senderAccount.balance -= transaction.amount;
      receiverAccount.balance += transaction.amount - transaction.fee;
    }

    await senderAccount.save();
    await receiverAccount.save();

    transaction.status = 'completed';
    await transaction.save();

    return transaction;
  }
}
