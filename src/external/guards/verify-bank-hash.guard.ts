import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Bank } from 'src/models/banks/schemas/bank.schema';
import { CryptoUtil } from 'src/utils/crypto.util';

@Injectable()
export class VerifyBankHashGuard implements CanActivate {
  constructor(
    @InjectModel(Bank.name) private bankModel: Model<Bank>,
    private cryptoUtil: CryptoUtil,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const hash = request.headers['x-hash'];
    const timestamp = request.headers['request-time'];
    const partnerCode = request.headers['partner-code'];

    if (!hash || !timestamp || !partnerCode) {
      throw new UnauthorizedException('Missing required headers');
    }

    const bank = await this.bankModel.findOne({ code: partnerCode });
    if (!bank) {
      throw new UnauthorizedException('Unknown bank partner');
    }

    // Create hash data based on request method
    let dataToHash;
    if (request.method === 'GET') {
      dataToHash = {
        accountNumber: request.query.accountNumber,
        timestamp,
      };
    } else {
      dataToHash = request.body;
    }

    const calculatedHash = this.cryptoUtil.generateAPIHash(
      dataToHash,
      timestamp,
      bank.secretKey,
    );

    console.log('Hash verification:', {
      received: hash,
      calculated: calculatedHash,
      data: dataToHash,
    });

    if (calculatedHash !== hash) {
      throw new UnauthorizedException('Invalid hash');
    }

    // Check timestamp to prevent replay attacks (5 minutes validity)
    const requestTime = new Date(timestamp).getTime();
    const now = Date.now();
    if (now - requestTime > 5 * 60 * 1000) {
      throw new UnauthorizedException('Request expired');
    }

    request.partner = bank;
    return true;
  }
}
