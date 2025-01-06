import { ApiProperty } from '@nestjs/swagger';

export class BankReconciliationDto {
  @ApiProperty()
  bankName: string;

  @ApiProperty()
  bankId: string;

  @ApiProperty()
  totalReceived: number;

  @ApiProperty()
  totalSent: number;

  @ApiProperty()
  transactionCount: number;

  @ApiProperty()
  transactions: TransactionRecordDto[];
}

export class TransactionRecordDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  type: 'sent' | 'received';

  @ApiProperty()
  amount: number;

  @ApiProperty()
  fromAccount: string;

  @ApiProperty()
  toAccount: string;

  @ApiProperty()
  content: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  status: string;
}

export class ReconciliationResponseDto {
  @ApiProperty()
  totalAmount: number;

  @ApiProperty()
  totalTransactions: number;

  @ApiProperty({ type: [BankReconciliationDto] })
  banks: BankReconciliationDto[];
}
