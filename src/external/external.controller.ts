import {
  Body,
  Controller,
  Get,
  Post,
  Headers,
  UseGuards,
  Query,
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

@ApiTags('External Bank Operations')
@Controller('external')
export class ExternalController {
  constructor(private readonly externalService: ExternalService) {}

  @Post('receive-transfer')
  @UseGuards(VerifyBankSignatureGuard, VerifyBankHashGuard) // Kiểm tra ở đây trước
  @ApiOperation({ summary: 'Receive transfer from other bank' })
  @ApiHeader({ name: 'Partner-Code', required: true })
  @ApiHeader({ name: 'Request-Time', required: true })
  @ApiHeader({ name: 'X-Hash', required: true })
  @ApiHeader({ name: 'X-Signature', required: true })
  @ApiResponse({ status: 201, description: 'Transfer received successfully' })
  @ApiResponse({ status: 400, description: 'Bad request or invalid data' })
  @ApiResponse({ status: 403, description: 'Invalid signature or hash' })
  async receiveTransfer(
    @Body() transferDto: ExternalTransferReceiveDto,
    @Headers() headers: Record<string, string>,
  ) {
    return this.externalService.processIncomingExternalTransfer(
      transferDto,
      headers,
    );
  }

  @Get('account-info')
  @UseGuards(VerifyBankHashGuard)
  @ApiOperation({ summary: 'Get account information' })
  @ApiHeader({ name: 'Partner-Code', required: true })
  @ApiHeader({ name: 'Request-Time', required: true })
  @ApiHeader({ name: 'X-Hash', required: true })
  @ApiQuery({ name: 'accountNumber', required: true, type: String })
  @ApiResponse({ status: 200, description: 'Account information retrieved' })
  @ApiResponse({ status: 404, description: 'Account not found' })
  @ApiResponse({ status: 403, description: 'Invalid hash' })
  async getAccountInfo(
    @Headers('Partner-Code') partnerCode: string,
    @Headers('Request-Time') timestamp: string,
    @Headers('X-Hash') hash: string,
    @Query('accountNumber') accountNumber: string,
  ) {
    return this.externalService.getInfo(accountNumber);
  }
}
