import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/auth/schemas/user.schema';
import { MailService } from 'src/mail/mail.service';
import { Account } from 'src/models/accounts/schemas/account.schema';
import { Bank } from 'src/models/banks/schemas/bank.schema';
import { Transaction } from 'src/models/transactions/schemas/transaction.schema';
import { JwtUtil } from 'src/utils/jwt.util';
import { RsaUtil } from 'src/utils/rsa.util';
import { ExternalTransferReceiveDto } from './external.dto';
import { CryptoUtil } from 'src/utils/crypto.util';

@Injectable()
export class ExternalService {
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

  async getInfo(accountNumber: string) {
    const account = await this.accountModel.findOne({ accountNumber });
    if (!account) {
      throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
    }
    return account;
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

      // Log the incoming data for debugging
      console.log('Processing transfer with data:', {
        partnerCode: transferDto.partnerCode,
        encodedData: transferDto.encodedData, // Changed from encryptedData to encodedData
      });

      // Use encodedData instead of encryptedData
      const decodedData = this.cryptoUtil.decodeTransactionData(
        transferDto.encodedData,
        partnerBank.publicKey,
        partnerBank.secretKey,
      );

      // Validate timestamp to prevent replay attacks
      const timestamp = new Date(decodedData.timestamp);
      const now = new Date();
      if (now.getTime() - timestamp.getTime() > 5 * 60 * 1000) {
        // 5 minutes
        throw new HttpException('Request expired', HttpStatus.BAD_REQUEST);
      }

      const sourceBank = await this.bankModel.findById(
        decodedData.sourceBankId,
      );
      if (!sourceBank) {
        throw new HttpException('Source bank not found', HttpStatus.NOT_FOUND);
      }

      const account = await this.accountModel.findOne({
        accountNumber: decodedData.toAccount,
      });
      if (!account) {
        throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
      }

      const transaction = new this.transactionModel({
        fromBank: sourceBank._id,
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
      console.error('Transfer processing error:', {
        error: error.message,
        data: transferDto,
      });
      throw new HttpException(
        'Failed to process transfer: ' + error.message,
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
