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
import { CryptoUtil } from '../utils/crypto.util';

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
    private cryptoUtil: CryptoUtil,
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
      const senderAccount = await this.accountModel.findOne({
        accountNumber: transaction.fromAccount,
      });

      if (!senderAccount) {
        throw new NotFoundException('Sender account not found');
      }

      // Calculate fee and total amount
      const fee = Math.floor(transaction.amount / 100); // 1% fee
      const totalAmount =
        transaction.feeType === 'sender'
          ? transaction.amount + fee
          : transaction.amount;

      if (senderAccount.balance < totalAmount) {
        throw new BadRequestException('Insufficient balance to cover fees');
      }

      // Prepare transaction data
      const transferData = {
        fromAccount: transaction.fromAccount,
        toAccount: transaction.toAccount,
        amount: transaction.amount,
        content: transaction.content,
        sourceBankId: this.configService.get('BANK_ID'),
        timestamp: new Date().toISOString(),
        fee: fee,
        feeType: transaction.feeType,
      };

      // Get partner bank details
      const partnerBank = await this.bankModel.findById(transaction.bankId);
      if (!partnerBank) {
        throw new NotFoundException('Partner bank not found');
      }

      console.log('Partner bank details:', {
        bankId: partnerBank._id,
        secretKey: partnerBank.secretKey,
        publicKey: partnerBank.publicKey.substring(0, 50) + '...',
      });

      // Encode the transaction data with signature and hash
      // const encodedData = this.cryptoUtil.encodeTransactionData(
      //   transferData,
      //   this.configService.get('BANK_PRIVATE_KEY'),
      //   partnerBank.secretKey,
      // );

      // Generate request timestamp
      const timestamp = new Date().toISOString();

      // Create request payload with partnerCode and stringified transferData
      const requestPayload = {
        partnerCode: partnerBank.code,
        transferData: JSON.stringify(transferData), // Convert data to string as expected
      };

      // Generate hash for request
      const hash = this.cryptoUtil.generateAPIHash(
        requestPayload,
        timestamp,
        partnerBank.secretKey,
      );

      console.log('Hash verification:', {
        payload: requestPayload,
        timestamp,
        secretKey: partnerBank.secretKey,
        hash,
      });

      // Generate signature for request
      const signature = this.cryptoUtil.signData(
        requestPayload,
        this.configService.get('BANK_PRIVATE_KEY'),
      );

      // Make API call with security headers
      console.log('Calling partner bank API:', {
        url: `${partnerBank.apiUrl}/external/receive-transfer`,
        bankCode: partnerBank.code,
        timestamp,
        headers: {
          'Partner-Code': partnerBank.code,
          'Request-Time': timestamp,
          'X-Hash': hash,
          'X-Signature': signature,
        },
      });

      console.log('Request payload:', requestPayload);

      const response = await axios.post(
        `${partnerBank.apiUrl}/external/receive-transfer`, // Sửa URL từ configService
        requestPayload, // Gửi payload dưới dạng object
        {
          headers: {
            'Partner-Code': partnerBank.code,
            'Request-Time': timestamp,
            'X-Signature': signature,
            'X-Hash': hash,
            'Content-Type': 'application/json',
          },
          timeout: Number(this.configService.get('API_TIMEOUT')) || 5000,
        },
      );

      if (response.data.success) {
        // Deduct money from sender's account including fee if sender pays
        await this.accountModel.findByIdAndUpdate(senderAccount._id, {
          $inc: { balance: -totalAmount },
        });

        // Update transaction status with fee details
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
      console.error('External transfer error details:', {
        error: error.message,
        code: error.code,
        response: error.response?.data,
        config: error.config,
      });
      // ...existing error handling code...
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

  async getExternalAccountInfo(accountNumber: string, bankId: string) {
    try {
      // Generate request timestamp
      const timestamp = new Date().toISOString();

      const partnerBank = await this.bankModel.findById(bankId);

      // Get partner bank details first
      // const partnerBank = await this.bankModel.findOne({
      //   code: ,
      // });

      if (!partnerBank) {
        throw new NotFoundException('Partner bank configuration not found');
      }

      // Create hash data in correct format
      const dataToHash = {
        accountNumber,
        timestamp,
      };

      // Generate hash
      const hash = this.cryptoUtil.generateAPIHash(
        dataToHash,
        timestamp,
        partnerBank.secretKey,
      );

      console.log('Request details:', {
        url: `${partnerBank.apiUrl}/external/account-info`,
        params: { accountNumber },
        headers: {
          'Partner-Code': partnerBank.code,
          'Request-Time': timestamp,
          'X-Hash': hash,
        },
      });

      const response = await axios.get(
        `${partnerBank.apiUrl}/external/account-info`,
        {
          params: { accountNumber },
          headers: {
            'Partner-Code': partnerBank.code,
            'Request-Time': timestamp,
            'X-Hash': hash,
            'Content-Type': 'application/json',
          },
          timeout: Number(this.configService.get('API_TIMEOUT')) || 5000,
        },
      );

      return response.data;
    } catch (error) {
      console.error('External account info error:', error);

      if (axios.isAxiosError(error)) {
        console.log('Response data:', error.response?.data);
        const status = error.response?.status || HttpStatus.SERVICE_UNAVAILABLE;
        const message =
          error.response?.data?.message || 'Failed to get account info';
        throw new HttpException(message, status);
      }

      throw new HttpException(
        'Failed to connect to partner bank',
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
  }

  async processIncomingExternalTransfer(
    transferDto: ExternalTransferReceiveDto,
  ) {
    try {
      const partnerBank = await this.bankModel.findOne({
        code: transferDto.partnerCode,
      });

      if (!partnerBank) {
        throw new HttpException('Unknown partner bank', HttpStatus.FORBIDDEN);
      }

      const decodedData = this.cryptoUtil.decodeTransactionData(
        transferDto.encodedData,
        //partnerBank.publicKey,
        //partnerBank.secretKey,
      );

      // Continue with existing transfer logic using decodedData
      const account = await this.accountModel.findOne({
        accountNumber: decodedData.toAccount,
      });
      if (!account) {
        throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
      }

      const transaction = new this.transactionModel({
        fromBank: partnerBank._id,
        fromAccount: decodedData.fromAccount,
        toAccount: decodedData.toAccount,
        amount: decodedData.amount,
        content: decodedData.content,
        type: 'external_receive',
        status: 'completed',
        feeType: decodedData.feeType,
        fee: decodedData.fee,
      });

      await transaction.save();

      account.balance += decodedData.amount;
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
