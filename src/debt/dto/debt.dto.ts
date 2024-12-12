import { ApiProperty } from '@nestjs/swagger';

export class DebtDetailDto {
  @ApiProperty({
    description: 'ID của khoản nợ',
    example: '507f1f77bcf86cd799439011',
  })
  _id: string;

  @ApiProperty({
    description: 'Thông tin người tạo nợ',
  })
  fromUser: {
    _id: string; // This will be ObjectId converted to string
    fullName: string;
    username: string;
  };

  @ApiProperty({
    description: 'Thông tin người nhận nợ',
  })
  toUser: {
    _id: string;
    fullName: string;
    username: string;
  };

  @ApiProperty()
  amount: number;

  @ApiProperty()
  content: string;

  @ApiProperty()
  status: string;

  @ApiProperty()
  createdAt: Date;
}

export class DebtSummaryDto {
  @ApiProperty({
    description: 'Tổng số tiền bạn đã cho mượn',
    example: 1000000,
  })
  totalLent: number;

  @ApiProperty({
    description: 'Tổng số tiền bạn đang mượn',
    example: 500000,
  })
  totalBorrowed: number;

  @ApiProperty({
    description: 'Danh sách các khoản nợ bạn tạo',
    type: [DebtDetailDto],
  })
  createdDebts: DebtDetailDto[];

  @ApiProperty({
    description: 'Danh sách các khoản nợ người khác gửi cho bạn',
    type: [DebtDetailDto],
  })
  receivedDebts: DebtDetailDto[];
}
