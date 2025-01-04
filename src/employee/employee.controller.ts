import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
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
import { BearerToken } from 'src/auth/decorators/auth.decorator';

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
    description: 'Deposit money to a customer account',
  })
  @ApiResponse({
    status: 200,
    description: 'Returns a success',
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

  @Get('searchAccount/:searchTerm')
  @ApiOperation({
    summary: 'Get account details by account number or username',
    description:
      'Return the account detail (username & account number) from the search term',
  })
  @ApiResponse({
    status: 200,
    description: 'Account details retrieved successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Account not found',
  })
  async getAccount(
    @BearerToken() accessToken: string,
    @Param('searchTerm') searchTerm: string,
  ) {
    const containsLetter = /[a-zA-Z]/.test(searchTerm); // Check if searchTerm contains any letters

    if (!containsLetter)
      return this.employeeService.getAccountByAccountNumber(
        accessToken,
        searchTerm,
      );
    else
      return this.employeeService.getAccountByUsername(accessToken, searchTerm);
  }
}
