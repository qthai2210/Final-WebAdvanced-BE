import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import { RecipientService } from './recipient.service';
import { BearerToken } from 'src/auth/decorators/auth.decorator';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { RecipientDto } from './recipient.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { UserRole } from 'src/auth/schemas/user.schema';

@Controller('recipients')
@ApiTags('Recipients')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.CUSTOMER)
@ApiBearerAuth('access-token') // Must match the name in main.ts
export class RecipientController {
  constructor(private readonly recipientService: RecipientService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new recipient' })
  @ApiResponse({
    status: 201,
    description: 'The recipient is created successfully.',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  @ApiResponse({
    status: 404,
    description: 'Payment account not found',
  })
  @ApiResponse({
    status: 500,
    description: 'Recipient already exists for this user',
  })
  async addRecipient(
    @BearerToken() accessToken: string,
    @Body() recipientDto: RecipientDto,
  ) {
    // log the access token
    console.log(accessToken);
    return this.recipientService.addRecipient(accessToken, recipientDto);
  }

  @Get()
  @ApiOperation({
    summary: 'Get the list of recipients',
  })
  @ApiResponse({
    status: 200,
    description: 'Received recipients successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  async getRecipients(@BearerToken() accessToken: string) {
    return this.recipientService.getRecipients(accessToken);
  }

  @Put()
  @ApiOperation({ summary: 'Update a recipient' })
  @ApiResponse({
    status: 200,
    description: 'Recipient was updated successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  @ApiResponse({
    status: 404,
    description: 'Recipient not found',
  })
  async updateRecipient(
    @BearerToken() accessToken: string,
    @Body() recipientDto: RecipientDto,
  ) {
    return this.recipientService.updateRecipient(accessToken, recipientDto);
  }

  @Delete(':recipientId')
  @ApiOperation({ summary: 'Delete a recipient' })
  @ApiResponse({
    status: 200,
    description: 'Recipient was deleted successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - User is not logged in',
  })
  @ApiResponse({
    status: 404,
    description: 'Recipient not found',
  })
  async removeRecipient(
    @BearerToken() accessToken: string,
    @Param('recipientId') recipientId: string,
  ) {
    return this.recipientService.removeRecipient(accessToken, recipientId);
  }
}
