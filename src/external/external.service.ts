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
    const account = await this.accountModel
      .findOne({ accountNumber })
      .populate('userId', ['username', 'email', 'fullName']) // Chỉ định các trường muốn lấy từ User
      .exec();

    if (!account) {
      throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
    }

    // Transform response data if needed
    const response = {
      accountNumber: account.accountNumber,
      username: account.userId?.username,
      fullName: account.userId?.fullName,
      email: account.userId?.email,
    };

    return response;
  }

  async processIncomingExternalTransfer(
    transferDto: ExternalTransferReceiveDto,
    bank: any,
  ) {
    try {
      // const partnerBank = await this.bankModel.findOne({
      //   code: headers['x-bank-code'],
      // });

      // if (!partnerBank) {
      //   throw new HttpException('Unknown partner bank', HttpStatus.FORBIDDEN);
      // }

      // Validate request timestamp from header
      // const requestTime = headers['x-timestamp'];
      // const signature = headers['x-signature'];
      // const receivedHash = headers['x-hash'];

      // if (!requestTime || !signature || !receivedHash) {
      //   throw new HttpException(
      //     'Missing required headers',
      //     HttpStatus.BAD_REQUEST,
      //   );
      // }
      // // Verify timestamp
      // const timestamp = new Date(requestTime);
      // const now = new Date();
      // if (now.getTime() - timestamp.getTime() > 5 * 60 * 1000) {
      //   throw new HttpException('Request expired', HttpStatus.BAD_REQUEST);
      // }

      // // Verify hash of data
      // const requestPayload = {
      //   //partnerCode: transferDto.partnerCode,
      //   transferData: transferDto.transferData,
      // };
      // console.log('Request payload1:', requestPayload);
      // console.log('requestTime:', requestTime);
      // console.log('partnerBank.secretKey:', partnerBank.secretKey);

      // const calculatedHash = this.cryptoUtil.generateAPIHash(
      //   requestPayload, // Sửa lại dùng requestPayload thay vì transferDto
      //   requestTime,
      //   partnerBank.secretKey,
      // );
      // console.log('Calculated hash:', calculatedHash);
      // console.log('Received hash:', receivedHash);
      // if (calculatedHash !== receivedHash) {
      //   throw new HttpException('Invalid hash', HttpStatus.FORBIDDEN);
      // }

      // Verify signature of transfer data
      // const isValidSignature = this.cryptoUtil.verifySignature(
      //   requestPayload, // Verify entire payload
      //   signature,
      //   partnerBank.publicKey,
      // );

      // if (!isValidSignature) {
      //   console.error('Signature verification failed:', {
      //     receivedSignature: signature,
      //     payload: requestPayload,
      //     publicKey: partnerBank.publicKey.substring(0, 100) + '...',
      //   });
      //   throw new HttpException('Invalid signature', HttpStatus.FORBIDDEN);
      // }

      // Decode and process transfer data
      const decodedData = JSON.parse(transferDto.transferData);

      const sourceBank = bank;
      console.log('Source bank:', sourceBank);
      const account = await this.accountModel.findOne({
        accountNumber: decodedData.toAccount,
      });
      if (!account) {
        throw new HttpException('Account not found', HttpStatus.NOT_FOUND);
      }

      const transaction = new this.transactionModel({
        fromBankId: sourceBank._id,
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

      return {
        success: true,
      };
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

  async getCurrentBank() {
    const bank = {
      code: this.configService.get('BANK_CODE'),
      name: this.configService.get('BANK_NAME'),
      apiUrl: this.configService.get('BANK_API_URL'),
      secretKey: this.configService.get('BANK_SECRET_KEY'),
      publicKey: this.configService.get('BANK_PUBLIC_KEY'),
      privateKey: this.configService.get('BANK_PRIVATE_KEY'),
    };

    return {
      success: true,
      data: bank,
      timestamp: new Date().toISOString(),
    };
  }

  async getAllBanks() {
    const banks = await this.bankModel
      .find()
      .select('name code apiUrl') // Only select necessary fields, excluding sensitive data
      .lean()
      .exec();

    return {
      success: true,
      data: banks,
      timestamp: new Date().toISOString(),
    };
  }
}
