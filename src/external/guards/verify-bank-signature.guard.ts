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
export class VerifyBankSignatureGuard implements CanActivate {
  constructor(
    @InjectModel(Bank.name) private bankModel: Model<Bank>,
    private cryptoUtil: CryptoUtil,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const signature = request.headers['x-signature'];
    const hash = request.headers['x-hash']; // Lấy hash từ header
    const partnerCode = request.headers['x-bank-code'];

    if (!signature || !partnerCode || !hash) {
      throw new UnauthorizedException(
        'Missing signature, hash or partner code',
      );
    }

    const bank = await this.bankModel.findOne({ code: partnerCode });
    if (!bank || !bank.publicKey) {
      throw new UnauthorizedException('Invalid bank partner configuration');
    }

    console.log('Verifying signature with:', {
      hash,
      signature,
      publicKey: bank.publicKey.substring(0, 100) + '...',
    });

    try {
      // Verify signature với hash
      const isValid = this.cryptoUtil.verifySignature(
        hash, // Dùng hash thay vì request body
        signature,
        bank.publicKey,
      );

      if (!isValid) {
        throw new UnauthorizedException('Invalid signature');
      }

      request.partner = bank;
      return true;
    } catch (error) {
      console.error('Signature verification failed:', error);
      throw new UnauthorizedException(
        `Signature verification failed: ${error.message}`,
      );
    }
  }
}
