import { Controller, Get, Post } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { AccountsService } from './accounts.service';
import { BearerToken } from 'src/auth/decorators/auth.decorator';

@ApiTags('Accounts')
@Controller('accounts')
@ApiBearerAuth()
export class AccountsController {
  constructor(private readonly accountsService: AccountsService) {}

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
    return await this.accountsService.getUserAccounts(accessToken);
  }
}
