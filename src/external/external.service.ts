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
    headers: Record<string, string>,
  ) {
    try {
      const partnerBank = await this.bankModel.findOne({
        code: transferDto.partnerCode,
      });

      if (!partnerBank) {
        throw new HttpException('Unknown partner bank', HttpStatus.FORBIDDEN);
      }

      // Validate request timestamp from header
      const requestTime = headers['request-time'];
      const signature = headers['x-signature'];
      const receivedHash = headers['x-hash'];

      if (!requestTime || !signature || !receivedHash) {
        throw new HttpException(
          'Missing required headers',
          HttpStatus.BAD_REQUEST,
        );
      }

      // Verify timestamp
      const timestamp = new Date(requestTime);
      const now = new Date();
      if (now.getTime() - timestamp.getTime() > 5 * 60 * 1000) {
        throw new HttpException('Request expired', HttpStatus.BAD_REQUEST);
      }

      // Verify hash of data
      const requestPayload = {
        partnerCode: transferDto.partnerCode,
        transferData: transferDto.transferData,
      };

      const calculatedHash = this.cryptoUtil.generateAPIHash(
        requestPayload, // Sửa lại dùng requestPayload thay vì transferDto
        requestTime,
        partnerBank.secretKey,
      );

      if (calculatedHash !== receivedHash) {
        throw new HttpException('Invalid hash', HttpStatus.FORBIDDEN);
      }

      // Verify signature of transfer data
      const isValidSignature = this.cryptoUtil.verifySignature(
        requestPayload, // Verify entire payload
        signature,
        partnerBank.publicKey,
      );

      if (!isValidSignature) {
        console.error('Signature verification failed:', {
          receivedSignature: signature,
          payload: requestPayload,
          publicKey: partnerBank.publicKey.substring(0, 100) + '...',
        });
        throw new HttpException('Invalid signature', HttpStatus.FORBIDDEN);
      }

      // Decode and process transfer data
      const decodedData = this.cryptoUtil.decodeTransactionData(
        transferDto.transferData,
      );

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
