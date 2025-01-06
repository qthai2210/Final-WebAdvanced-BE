import {
  Body,
  Controller,
  Get,
  Post,
  UseGuards,
  Query,
  Req,
} from '@nestjs/common';
import { ExternalService } from './external.service';
import {
  ApiOperation,
  ApiHeader,
  ApiResponse,
  ApiTags,
  ApiQuery,
} from '@nestjs/swagger';
import { ExternalTransferReceiveDto } from './external.dto';
import { VerifyBankSignatureGuard } from './guards/verify-bank-signature.guard';
import { VerifyBankHashGuard } from './guards/verify-bank-hash.guard';
import { CryptoUtil } from 'src/utils/crypto.util';
import { ConfigService } from '@nestjs/config';

@ApiTags('External Bank Operations')
@Controller('external')
export class ExternalController {
  constructor(
    private readonly externalService: ExternalService,
    private readonly cryptoUtil: CryptoUtil,
    private readonly configService: ConfigService,
  ) {}

  @Post('receive-transfer')
  @UseGuards(VerifyBankSignatureGuard, VerifyBankHashGuard) // Kiểm tra ở đây trước
  @ApiOperation({ summary: 'Receive transfer from other bank' })
  @ApiHeader({ name: 'x-bank-code', required: true })
  @ApiHeader({ name: 'x-timestamp', required: true })
  @ApiHeader({ name: 'x-hash', required: true })
  @ApiHeader({ name: 'x-signature', required: true })
  @ApiResponse({ status: 201, description: 'Transfer received successfully' })
  @ApiResponse({ status: 400, description: 'Bad request or invalid data' })
  @ApiResponse({ status: 403, description: 'Invalid signature or hash' })
  async receiveTransfer(
    @Body() transferDto: ExternalTransferReceiveDto,
    @Req() request,
  ) {
    const bank = request.partner;
    const headers = request.headers;
    const requestTime = headers['x-timestamp'];
    const signature = headers['x-signature'];
    const receivedHash = headers['x-hash'];
    const hash = `${requestTime}${signature}${receivedHash}`;
    // Ký và gửi lại thông báo cho ngân hàng gốc
    const signatureResponse = this.cryptoUtil.signData(
      //requestPayload,
      hash,
      this.configService.get('BANK_PRIVATE_KEY'),
    );
    const result = await this.externalService.processIncomingExternalTransfer(
      transferDto,
      bank,
    );
    return {
      ...result,
      headers: {
        'x-signature': signatureResponse,
      },
    };
  }

  @Get('account-info')
  @UseGuards(VerifyBankHashGuard)
  @ApiOperation({ summary: 'Get account information' })
  @ApiHeader({ name: 'x-bank-code', required: true })
  @ApiHeader({ name: 'x-timestamp', required: true })
  @ApiHeader({ name: 'x-hash', required: true })
  @ApiQuery({ name: 'accountNumber', required: true, type: String })
  @ApiResponse({ status: 200, description: 'Account information retrieved' })
  @ApiResponse({ status: 404, description: 'Account not found' })
  @ApiResponse({ status: 403, description: 'Invalid hash' })
  async getAccountInfo(@Query('accountNumber') accountNumber: string) {
    return this.externalService.getInfo(accountNumber);
  }
}
