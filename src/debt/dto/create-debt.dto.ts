import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class CreateDebtDto {
  @ApiProperty({
    description: 'ID của người bị nợ',
    example: '6756e5f6f67a59a64bc778d7',
  })
  @IsNotEmpty()
  @IsString()
  toUserId: string;

  @ApiProperty({
    description: 'Số tiền nợ',
    example: 1000000,
  })
  @IsNotEmpty()
  @IsNumber()
  amount: number;

  @ApiProperty({
    description: 'Nội dung nhắc nợ',
    example: 'Tiền ăn trưa ngày 20/12',
  })
  @IsString()
  content: string;
}
