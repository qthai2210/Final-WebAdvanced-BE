import { ApiProperty } from '@nestjs/swagger';
import { Bank } from 'src/models/banks/schemas/bank.schema';

export class TransactionHistoryQueryDto {
  @ApiProperty({
    description: 'Account number to get transaction history',
    example: '1234567890',
  })
  accountNumber: string;

  @ApiProperty({
    description: 'Type of transactions to filter',
    enum: ['all', 'received', 'sent', 'debt_payment'],
    default: 'all',
    required: false,
  })
  type?: 'all' | 'received' | 'sent' | 'debt_payment';

  @ApiProperty({
    description: 'Page number for pagination',
    minimum: 1,
    default: 1,
    required: false,
  })
  page?: number = 1;

  @ApiProperty({
    description: 'Number of items per page',
    minimum: 1,
    maximum: 50,
    default: 10,
    required: false,
  })
  limit?: number = 10;

  @ApiProperty({
    description: 'Start date for filtering transactions',
    type: Date,
    required: false,
  })
  fromDate?: Date;

  @ApiProperty({
    description: 'End date for filtering transactions',
    type: Date,
    required: false,
  })
  toDate?: Date;
}

export class TransactionHistoryResponseDto {
  @ApiProperty({
    description: 'Transaction ID',
    example: '507f1f77bcf86cd799439011',
  })
  id: string;

  @ApiProperty({
    description: 'Type of transaction',
    enum: [
      'internal_transfer',
      'external_transfer',
      'debt_payment',
      'deposit',
      'external_receive',
    ],
    example: 'internal_transfer',
  })
  type: string;

  @ApiProperty({
    description: 'Transaction amount',
    example: 1000000,
  })
  amount: number;

  @ApiProperty({
    description: 'Sender account number',
    example: '1234567890',
  })
  fromAccount: string;

  @ApiProperty({
    description: 'Receiver account number',
    example: '0987654321',
  })
  toAccount: string;

  @ApiProperty({
    description: 'Transaction content',
    example: 'Transfer money',
  })
  content: string;

  @ApiProperty({
    description: 'Transaction fee',
    example: 0,
  })
  fee: number;

  @ApiProperty({
    description: 'Transaction status',
    enum: ['pending', 'completed', 'failed'],
    example: 'completed',
  })
  status: string;

  @ApiProperty({
    description: 'Transaction creation date',
    type: Date,
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Transaction direction relative to account',
    enum: ['in', 'out'],
    example: 'in',
  })
  direction: 'in' | 'out';

  @ApiProperty({
    description: 'Bank ID for external transfers',
    required: false,
    example: '507f1f77bcf86cd799439011',
  })
  bankId?: Bank;
  fromBankId?: Bank;
  toBankId?: Bank;
}
