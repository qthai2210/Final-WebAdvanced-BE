import { Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AccountsService } from './accounts.service';
import { BearerToken } from 'src/auth/decorators/auth.decorator';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { UserRole } from 'src/auth/schemas/user.schema';

@ApiTags('Accounts')
@Controller('accounts')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.CUSTOMER)
@ApiBearerAuth('access-token')
export class AccountsController {
  constructor(private readonly accountsService: AccountsService) { }

  @Post()
  @ApiOperation({ summary: 'Create a new payment account' })
  @ApiResponse({
    status: 201,
    description: 'A new payment account is created',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  async createOne(@BearerToken() accessToken: string) {
    return this.accountsService.createOne(accessToken);
  }

  @Get()
  @ApiOperation({ summary: "Get the list of user's accounts" })
  @ApiResponse({
    status: 201,
    description: "Received user's accounts successfully",
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - No accounts found for the current user',
  })
  async getUserAccounts(@BearerToken() accessToken: string) {
    console.log(accessToken);
    return await this.accountsService.getUserAccounts(accessToken);
  }

  @Get(':accountNumber')
  @ApiOperation({ summary: 'Get account details by account number' })
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
  async getAccountByAccountNumber(
    @BearerToken() accessToken: string,
    @Param('accountNumber') accountNumber: string,
  ) {
    return this.accountsService.getAccountByAccountNumber(
      accessToken,
      accountNumber,
    );
  }
}
