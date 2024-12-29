import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Transaction } from '../models/transactions/schemas/transaction.schema';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from './dto/transaction-history.dto';
import {
  ExternalTransferDto,
  ExternalTransferReceiveDto,
  InternalTransferDto,
} from './dto/transaction-create.dto';
import { Account } from 'src/models/accounts/schemas/account.schema';
import { MailService } from 'src/mail/mail.service';
import { JwtUtil } from 'src/utils/jwt.util';
import { VerifyOtpTransactionDto } from './dto/verify-otp.dto';
import { User } from 'src/auth/schemas/user.schema';
// import { InjectRepository } from '@nestjs/typeorm';
// import { Repository } from 'typeorm';
import { Bank } from 'src/models/banks/schemas/bank.schema';
import axios from 'axios';
import { ConfigService } from '@nestjs/config';
import { RsaUtil } from '../utils/rsa.util';

@Injectable()
export class TransactionService {
  constructor(
    @InjectModel(Transaction.name) private transactionModel: Model<Transaction>,
    @InjectModel(Account.name) private accountModel: Model<Account>,
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(Bank.name) private bankModel: Model<Bank>,
    private mailService: MailService,
    private JWTUtil: JwtUtil,
    private configService: ConfigService,
    private rsaUtil: RsaUtil,
  ) {}

  async getTransactionHistory(
    query: TransactionHistoryQueryDto,
  ): Promise<TransactionHistoryResponseDto[]> {
    const {
      accountNumber,
      type = 'all',
      page = 1,
      limit,
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
            feeType: 1,
            status: 1,
            createdAt: 1,
            updatedAt: 1,
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

    const { toAccount, amount, content, feeType } = internalTransferDto;

    const receiverAccount = await this.accountModel.findOne({
      accountNumber: toAccount,
    });

    if (!fromAccount || !receiverAccount) {
      throw new NotFoundException('Account not found');
    }

    const fee = Math.floor(amount / 100); // 1% fee
    const totalAmount = feeType === 'sender' ? amount + fee : amount;

    if (fromAccount.balance < totalAmount) {
      throw new BadRequestException('Insufficient balance');
    }

    const transaction = new this.transactionModel({
      fromAccount: fromAccount.accountNumber,
      toAccount: toAccount,
      amount: amount,
      content: content,
      fee: fee,
      feeType: feeType,
      status: 'pending',
      type: 'internal_transfer',
    });

    const savedTransaction = await transaction.save();

    const senderUser = await this.userModel.findById(fromAccount.userId);
    if (!senderUser) {
      throw new NotFoundException('Sender user not found');
    }

    await this.mailService.sendOtpToVerifyTransaction(
      senderUser.email,
      savedTransaction._id.toString(),
    );

    return savedTransaction;
  }

  async verifyOtp(verifyOtpDto: VerifyOtpTransactionDto): Promise<Transaction> {
    const { otp, transactionId, type } = verifyOtpDto;

    const transaction = await this.transactionModel.findById(transactionId);
    if (!transaction) {
      throw new NotFoundException('Transaction not found');
    }

    const isValidOtp = await this.mailService.verifyOtpTransaction(
      transactionId,
      otp,
    );

    if (!isValidOtp) {
      throw new UnauthorizedException('Invalid OTP');
    }

    if (type === 'internal') {
      return this.processInternalTransfer(transaction);
    } else {
      return this.processExternalTransfer(transaction);
    }
  }

  private async processInternalTransfer(
    transaction: Transaction,
  ): Promise<Transaction> {
    const senderAccount = await this.accountModel.findOne({
      accountNumber: transaction.fromAccount,
    });
    const receiverAccount = await this.accountModel.findOne({
      accountNumber: transaction.toAccount,
    });

    if (!senderAccount || !receiverAccount) {
      throw new NotFoundException('Account not found');
    }

    // Calculate amounts based on fee type
    const fee = transaction.fee || 0;
    if (transaction.feeType === 'sender') {
      senderAccount.balance -= transaction.amount + fee;
      receiverAccount.balance += transaction.amount;
    } else {
      senderAccount.balance -= transaction.amount;
      receiverAccount.balance += transaction.amount - fee;
    }

    // Save the updated balances
    await Promise.all([
      this.accountModel.findByIdAndUpdate(senderAccount._id, {
        $set: { balance: senderAccount.balance },
      }),
      this.accountModel.findByIdAndUpdate(receiverAccount._id, {
        $set: { balance: receiverAccount.balance },
      }),
    ]);

    // Update transaction status
    const updatedTransaction = await this.transactionModel.findByIdAndUpdate(
      transaction._id,
      { $set: { status: 'completed' } },
      { new: true },
    );

    if (!updatedTransaction) {
      throw new NotFoundException('Failed to update transaction');
    }

    return updatedTransaction;
  }

  private async processExternalTransfer(
    transaction: Transaction,
  ): Promise<Transaction> {
    try {
      console.log('Preparing external transfer request');

      // First check sender's balance
      const senderAccount = await this.accountModel.findOne({
        accountNumber: transaction.fromAccount,
      });

      if (!senderAccount) {
        throw new NotFoundException('Sender account not found');
      }

      if (senderAccount.balance < transaction.amount) {
        throw new BadRequestException('Insufficient balance');
      }

      // Calculate fee if applicable
      const fee = transaction.fee || Math.floor(transaction.amount / 100); // 1% fee
      const totalAmount =
        transaction.feeType === 'sender'
          ? transaction.amount + fee
          : transaction.amount;

      if (senderAccount.balance < totalAmount) {
        throw new BadRequestException('Insufficient balance to cover fees');
      }

      // Prepare payload for external bank
      const payload = {
        fromAccount: transaction.fromAccount,
        toAccount: transaction.toAccount,
        amount: transaction.amount,
        content: transaction.content || 'External Transfer',
        sourceBankId: this.configService.get('BANK_ID'),
        sourceTransactionId: transaction._id.toString(),
        fee: fee,
        feeType: transaction.feeType,
        timestamp: new Date().toISOString(), // Add timestamp for security
      };

      // Encrypt the payload
      const encryptedPayload = this.rsaUtil.encryptWithPublicKey(payload);

      console.log('Sending encrypted request');

      const response = await axios.post(
        `${this.configService.get('EXTERNAL_BANK_API_URL')}/transactions/external-transfer/receive`,
        { encryptedData: encryptedPayload },
        {
          headers: {
            'Content-Type': 'application/json',
          },
          timeout: 5000,
        },
      );

      console.log('Received response:', response.data);

      if (response.data.success) {
        // Deduct money from sender's account
        await this.accountModel.findByIdAndUpdate(senderAccount._id, {
          $inc: { balance: -totalAmount },
        });

        // Update transaction status
        const updatedTransaction =
          await this.transactionModel.findByIdAndUpdate(
            transaction._id,
            {
              $set: {
                status: 'completed',
                fee: fee,
                finalAmount: totalAmount,
              },
            },
            { new: true },
          );

        return updatedTransaction;
      }

      throw new HttpException(
        'External transfer failed: ' +
          (response.data.message || 'Unknown error'),
        HttpStatus.BAD_REQUEST,
      );
    } catch (error) {
      console.error(
        'External transfer error:',
        error.response?.data || error.message,
      );

      // Update transaction to failed status
      await this.transactionModel.findByIdAndUpdate(transaction._id, {
        $set: {
          status: 'failed',
          errorMessage: error.response?.data?.message || error.message,
        },
      });

      if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        throw new HttpException(
          `External transfer failed: ${error.response.data.message || 'Server Error'}`,
          error.response.status || HttpStatus.BAD_REQUEST,
        );
      } else if (error.request) {
        // The request was made but no response was received
        throw new HttpException(
          'External transfer failed: No response from external bank',
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      } else {
        // Something happened in setting up the request that triggered an Error
        throw new HttpException(
          'External transfer failed: ' + error.message,
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }
    }
  }

  async createExternalTransfer(
    accessToken: string,
    transferDto: ExternalTransferDto,
  ) {
    const decoded = this.JWTUtil.decodeJwt(accessToken);

    const bank = await this.bankModel.findById(transferDto.bankId);
    if (!bank) {
      throw new HttpException('Bank not found', HttpStatus.NOT_FOUND);
    }

    const account = await this.accountModel.findOne({ userId: decoded.sub });
    if (!account) {
      throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
    }

    const transaction = new this.transactionModel({
      fromAccount: account.accountNumber,
      toAccount: transferDto.toAccount,
      amount: transferDto.amount,
      content: transferDto.content,
      type: 'external_transfer',
      status: 'pending',
      feeType: transferDto.feeType,
      bankId: transferDto.bankId,
      toBankId: bank._id,
    });

    await this.transactionModel.create(transaction);

    const senderUser = await this.userModel.findById(account.userId);
    if (!senderUser) {
      throw new NotFoundException('User not found');
    }

    // Send OTP to the sender's email
    await this.mailService.sendOtpToVerifyTransaction(
      senderUser.email,
      transaction._id.toString(),
    );

    return { transactionId: transaction.id };
  }

  async processIncomingExternalTransfer(
    transferDto: ExternalTransferReceiveDto,
  ) {
    try {
      // Decrypt the incoming data
      const decryptedData = this.rsaUtil.decryptWithPrivateKey(
        transferDto.encryptedData,
      );

      // Validate timestamp to prevent replay attacks
      const timestamp = new Date(decryptedData.timestamp);
      const now = new Date();
      if (now.getTime() - timestamp.getTime() > 5 * 60 * 1000) {
        // 5 minutes
        throw new HttpException('Request expired', HttpStatus.BAD_REQUEST);
      }

      const sourceBank = await this.bankModel.findById(
        decryptedData.sourceBankId,
      );
      if (!sourceBank) {
        throw new HttpException('Source bank not found', HttpStatus.NOT_FOUND);
      }

      const account = await this.accountModel.findOne({
        accountNumber: decryptedData.toAccount,
      });
      if (!account) {
        throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
      }

      const transaction = new this.transactionModel({
        fromBank: sourceBank._id,
        fromAccount: decryptedData.fromAccount,
        toAccount: decryptedData.toAccount,
        amount: decryptedData.amount,
        content: decryptedData.content,
        type: 'external_receive',
        status: 'completed',
        feeType: decryptedData.feeType,
        fee: decryptedData.fee,
      });

      await transaction.save();

      account.balance += decryptedData.amount;
      await account.save();

      return { success: true };
    } catch (error) {
      console.error('Decryption error:', error);
      throw new HttpException(
        'Failed to process encrypted transfer',
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
