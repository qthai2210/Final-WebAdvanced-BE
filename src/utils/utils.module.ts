import { Global, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtUtil } from './jwt.util';
import { RsaUtil } from './rsa.util';
import { CryptoUtil } from './crypto.util';

@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get('JWT_SECRET'),
      }),
    }),
  ],
  providers: [JwtUtil, RsaUtil, CryptoUtil],
  exports: [JwtUtil, RsaUtil, CryptoUtil], // Add RsaUtil to exports
})
export class UtilsModule {}
