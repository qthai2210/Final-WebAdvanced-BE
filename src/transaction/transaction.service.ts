import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Transaction } from '../models/transactions/schemas/transaction.schema';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from './dto/transaction-history.dto';
import {
  ExternalTransferDto,
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
import { ReconciliationQueryDto } from './dto/reconciliation-query.dto';
import { ReconciliationResponseDto } from './dto/reconciliation-response.dto';

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
        { $skip: (pageNum - 1) * limitNum },
        { $limit: limitNum },
        {
          $lookup: {
            from: 'banks',
            localField: 'bankId',
            foreignField: '_id',
            as: 'mainBank',
          },
        },
        {
          $lookup: {
            from: 'banks',
            localField: 'fromBankId',
            foreignField: '_id',
            as: 'fromBank',
          },
        },
        {
          $lookup: {
            from: 'banks',
            localField: 'toBankId',
            foreignField: '_id',
            as: 'toBank',
          },
        },
        {
          $project: {
            type: 1,
            amount: 1,
            fromAccount: 1,
            toAccount: 1,
            content: 1,
            fee: 1,
            status: 1,
            createdAt: 1,
            updatedAt: 1,
            bankName: {
              $cond: {
                if: { $eq: ['$type', 'external_receive'] },
                then: { $arrayElemAt: ['$fromBank.name', 0] },
                else: {
                  $cond: {
                    if: { $eq: ['$type', 'external_transfer'] },
                    then: { $arrayElemAt: ['$toBank.name', 0] },
                    else: { $arrayElemAt: ['$mainBank.name', 0] },
                  },
                },
              },
            },
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
        //requestPayload,
        hash,
        this.configService.get('BANK_PRIVATE_KEY'),
      );

      // Make API call with security headers
      console.log('Calling partner bank API:', {
        url: `${partnerBank.apiUrl}/external/receive-transfer`,
        bankCode: partnerBank.code,
        timestamp,
        headers: {
          'x-bank-code': this.configService.get('BANK_CODE'),
          'x-timestamp': timestamp,
          'x-hash': hash,
          'x-signature': signature,
        },
      });

      console.log('Request payload:', requestPayload);

      const response = await axios.post(
        `${partnerBank.apiUrl}/external/accounts/${transaction.toAccount}/deposit`, // Sửa URL từ configService
        requestPayload, // Gửi payload dưới dạng object
        {
          headers: {
            'x-bank-code': this.configService.get('BANK_CODE'),
            'x-timestamp': timestamp,
            'x-signature': signature,
            'x-hash': hash,
            'Content-Type': 'application/json',
          },
          timeout: Number(this.configService.get('API_TIMEOUT')) || 5000,
        },
      );

      console.log('Response data:', response.data);
      console.log('Response header:', response.headers);

      // Get components used to generate signature from response
      const responseSignature = response.headers['x-signature'];

      // Recreate hash string that was signed
      const hashString = response.headers['x-hash'];
      console.log(responseSignature, partnerBank.publicKey);
      console.log('Hash string:', hashString);

      // Verify the response signature
      const isValidSignature = this.cryptoUtil.verifySignature(
        hashString, // Use same hash string that was signed
        responseSignature,
        partnerBank.publicKey,
      );

      console.log('Signature verification:', isValidSignature);

      if (!isValidSignature) {
        throw new HttpException(
          'Invalid response signature',
          HttpStatus.FORBIDDEN,
        );
      }

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
      // const dataToHash = {
      //accountNumber,
      //  timestamp,
      //};

      // Generate hash
      const hash = this.cryptoUtil.generateAPIHash(
        {},
        timestamp,
        partnerBank.secretKey,
      );

      console.log('Request details:', {
        url: `${partnerBank.apiUrl}/external/account-info`,
        params: { accountNumber },
        headers: {
          'x-bank-code': this.configService.get('BANK_CODE'),
          'x-timestamp': timestamp,
          'x-hash': hash,
        },
      });

      const response = await axios.get(
        `${partnerBank.apiUrl}/external/accounts/${accountNumber}`,
        {
          //params: { accountNumber },
          headers: {
            'x-bank-code': this.configService.get('BANK_CODE'),
            'x-timestamp': timestamp,
            'x-hash': hash,
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

  // async processIncomingExternalTransfer(
  //   transferDto: ExternalTransferReceiveDto,
  // ) {
  //   try {
  //     const partnerBank = await this.bankModel.findOne({
  //       code: transferDto.partnerCode,
  //     });

  //     if (!partnerBank) {
  //       throw new HttpException('Unknown partner bank', HttpStatus.FORBIDDEN);
  //     }

  //     const decodedData = this.cryptoUtil.decodeTransactionData(
  //       transferDto.encodedData,
  //       //partnerBank.publicKey,
  //       //partnerBank.secretKey,
  //     );

  //     // Continue with existing transfer logic using decodedData
  //     const account = await this.accountModel.findOne({
  //       accountNumber: decodedData.toAccount,
  //     });
  //     if (!account) {
  //       throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
  //     }

  //     const transaction = new this.transactionModel({
  //       fromBank: partnerBank._id,
  //       fromAccount: decodedData.fromAccount,
  //       toAccount: decodedData.toAccount,
  //       amount: decodedData.amount,
  //       content: decodedData.content,
  //       type: 'external_receive',
  //       status: 'completed',
  //       feeType: decodedData.feeType,
  //       fee: decodedData.fee,
  //     });

  //     await transaction.save();

  //     account.balance += decodedData.amount;
  //     await account.save();

  //     return { success: true };
  //   } catch (error) {
  //     console.error('Decryption error:', error);
  //     throw new HttpException(
  //       'Failed to process encrypted transfer',
  //       HttpStatus.BAD_REQUEST,
  //     );
  //   }
  // }

  async getReconciliationReport(
    query: ReconciliationQueryDto,
  ): Promise<ReconciliationResponseDto> {
    try {
      const page = Number(query.page) || 1;
      const limit = Number(query.limit) || 10;
      const skip = (page - 1) * limit;

      const matchQuery: any = {
        status: 'completed',
        $or: [{ type: 'external_transfer' }, { type: 'external_receive' }],
      };

      // Add date filters if provided
      if (query.fromDate && query.toDate) {
        const fromDate = new Date(query.fromDate);
        const toDate = new Date(query.toDate);
        if (!isNaN(fromDate.getTime()) && !isNaN(toDate.getTime())) {
          matchQuery.createdAt = {
            $gte: fromDate,
            $lte: toDate,
          };
        }
      }

      // Add bank filter if provided
      if (query.bankId) {
        const bankObjectId = new Types.ObjectId(query.bankId);
        matchQuery.$or = [
          { bankId: bankObjectId },
          { fromBankId: bankObjectId },
          { toBankId: bankObjectId },
        ];
      }

      const [transactions, total] = await Promise.all([
        this.transactionModel
          .find(matchQuery)
          .populate('bankId')
          .populate('fromBankId')
          .populate('toBankId')
          .skip(skip)
          .limit(limit)
          .exec(),
        this.transactionModel.countDocuments(matchQuery),
      ]);

      return {
        success: true,
        data: {
          data: transactions,
          metadata: {
            total,
            page: page.toString(),
            lastPage: Math.ceil(total / limit),
            limit: limit.toString(),
          },
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      console.error('Reconciliation error:', error);
      if (error.name === 'BSONTypeError' || error.name === 'CastError') {
        throw new HttpException(
          'Invalid date format or bank ID',
          HttpStatus.BAD_REQUEST,
        );
      }
      throw new HttpException(
        'Failed to generate reconciliation report',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
