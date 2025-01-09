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

export class ReconciliationMetadata {
  @ApiProperty()
  total: number;

  @ApiProperty()
  page: string;

  @ApiProperty()
  lastPage: number;

  @ApiProperty()
  limit: string;
}

export class ReconciliationData {
  @ApiProperty({ isArray: true })
  data: any[];

  @ApiProperty()
  metadata: ReconciliationMetadata;
}

export class ReconciliationResponseDto {
  @ApiProperty()
  success: boolean;

  @ApiProperty()
  data: ReconciliationData;

  @ApiProperty()
  timestamp: string;

  @ApiProperty()
  message?: string;
}
