import { Controller, Get, Query } from '@nestjs/common';
import { TransactionService } from './transaction.service';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from './dto/transaction-history.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('transactions')
@Controller('transactions')
export class TransactionController {
  constructor(private readonly transactionService: TransactionService) {}

  @Get('history')
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
}
