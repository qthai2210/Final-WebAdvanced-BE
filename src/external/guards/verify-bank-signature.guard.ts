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
    const partnerCode = request.headers['partner-code'];

    if (!signature || !partnerCode) {
      throw new UnauthorizedException('Missing signature or partner code');
    }

    const bank = await this.bankModel.findOne({ code: partnerCode });
    if (!bank || !bank.publicKey) {
      throw new UnauthorizedException('Invalid bank partner configuration');
    }

    // Add debug logging
    console.log('Verifying signature with:', {
      partnerCode,
      publicKey: bank.publicKey.substring(0, 100) + '...',
      requestBody: JSON.stringify(request.body).substring(0, 100) + '...',
      signature: signature.substring(0, 50) + '...',
    });

    try {
      const isValid = this.cryptoUtil.verifySignature(
        request.body,
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
