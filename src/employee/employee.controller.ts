import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from 'src/transaction/dto/transaction-history.dto';
import { EmployeeService } from './employee.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/auth/schemas/user.schema';
import { DepositMoneyCreateDto } from './dto/deposit-money-create.dto';
import {
  createErrorResponse,
  createSuccessResponse,
} from 'src/ApiRespose/interface/response.interface';

@ApiTags('Employee')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.EMPLOYEE)
@ApiBearerAuth('access-token')
@Controller('employee')
export class EmployeeController {
  constructor(private readonly employeeService: EmployeeService) { }

  @Get('user-transaction-history')
  @ApiOperation({
    summary: 'Get transaction history',
    description: 'Get transaction history for a specific account with filters',
  })
  @ApiResponse({
    status: 200,
    description: 'Returns the transaction history',
    type: [TransactionHistoryQueryDto],
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
    return this.employeeService.getTransactionHistory(query);
  }

  @Post('deposit-money')
  @ApiOperation({
    summary: 'Deposit ',
    description: 'Get transaction history for a specific account with filters',
  })
  @ApiResponse({
    status: 200,
    description: 'Returns the transaction history',
    type: [TransactionHistoryQueryDto],
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT auth token is invalid or missing',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid query parameters',
  })
  async depositMoneyIntoCustomerAccount(
    @Body() body: DepositMoneyCreateDto,
  ): Promise<any> {
    try {
      const response =
        this.employeeService.depositMoneyIntoCustomerAccount(body);
      return createSuccessResponse(response);
    } catch (error) {
      return createErrorResponse(404, error);
    }
  }
}
