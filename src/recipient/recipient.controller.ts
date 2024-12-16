import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
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

@ApiTags('Recipients')
@ApiBearerAuth()
@Controller('recipients')
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

  @Delete(':accountNumber')
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
    @Param('accountNumber') accountNumber: string,
  ) {
    return this.recipientService.removeRecipient(accessToken, accountNumber);
  }
}
