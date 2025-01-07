import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { CryptoUtil } from 'src/utils/crypto.util';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SignatureResponseInterceptor implements NestInterceptor {
  constructor(
    private readonly cryptoUtil: CryptoUtil,
    private readonly configService: ConfigService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    return next.handle().pipe(
      map((data) => {
        const headers = request.headers;
        const requestTime = headers['x-timestamp'];
        const signature = headers['x-signature'];
        const receivedHash = headers['x-hash'];
        const hash = `${requestTime}${signature}${receivedHash}`;

        const signatureResponse = this.cryptoUtil.signData(
          hash,
          this.configService.get('BANK_PRIVATE_KEY'),
        );
        console.log('Signature response123:', signatureResponse);
        response.setHeader('x-signature', signatureResponse);
        response.setHeader('x-hash', hash);
        return data;
      }),
    );
  }
}
