import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { TransactionService } from './transaction.service';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from './dto/transaction-history.dto';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import {
  InternalTransferDto,
  ExternalTransferDto,
  ExternalTransferReceiveDto,
} from './dto/transaction-create.dto';
import { BearerToken } from 'src/auth/decorators/auth.decorator';
import { VerifyOtpTransactionDto } from './dto/verify-otp.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/auth/schemas/user.schema';

@ApiTags('transactions')
// @UseGuards(JwtAuthGuard, RolesGuard)
// @Roles(UserRole.CUSTOMER)
// @ApiBearerAuth('access-token')
@Controller('transactions')
export class TransactionController {
  constructor(private readonly transactionService: TransactionService) {}

  @Get('history')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.CUSTOMER)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Get transaction history',
    description: 'Get transaction history for a specific account with filters',
  })
  @ApiResponse({
    status: 200,
    description: 'Returns the transaction history',
    type: [TransactionHistoryResponseDto],
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT auth token is invalid or missing',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid query parameters',
  })
  async getTransactionHistory(
    @Query() query: TransactionHistoryQueryDto,
  ): Promise<TransactionHistoryResponseDto[]> {
    return this.transactionService.getTransactionHistory(query);
  }

  @Post('internal-transfer')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.CUSTOMER)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Initiate internal transfer' })
  @ApiResponse({ status: 201, description: 'Internal transfer initiated' })
  async initiateInternalTransfer(
    @Body() internalTransferDto: InternalTransferDto,
    @BearerToken() accessToken: string,
  ) {
    return this.transactionService.initiateInternalTransfer(
      accessToken,
      internalTransferDto,
    );
  }

  @Post('verify-otp')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.CUSTOMER)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Verify OTP for any transaction type' })
  @ApiResponse({
    status: 200,
    description: 'OTP verified and transaction completed',
  })
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpTransactionDto) {
    return this.transactionService.verifyOtp(verifyOtpDto);
  }

  @Post('external-transfer')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.CUSTOMER)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Create external transfer to other bank' })
  async createExternalTransfer(
    @BearerToken() accessToken: string,
    @Body() transferDto: ExternalTransferDto,
  ) {
    return this.transactionService.createExternalTransfer(
      accessToken,
      transferDto,
    );
  }

  @Post('external-transfer/receive')
  @ApiOperation({ summary: 'Receive transfer from other bank' })
  async receiveExternalTransfer(
    @Body() transferDto: ExternalTransferReceiveDto,
  ) {
    return this.transactionService.processIncomingExternalTransfer(transferDto);
  }
}
