import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class CreateDebtDto {
  @ApiProperty({
    description: 'Số tài khoản người bị nợ',
    example: '9876543210',
  })
  @IsNotEmpty({ message: 'Số tài khoản không được để trống' })
  @IsString({ message: 'Số tài khoản phải là chuỗi ký tự' })
  accountNumber: string;

  @ApiProperty({
    description: 'Số tiền nợ',
    example: 1000000,
    minimum: 1000,
  })
  @IsNotEmpty({ message: 'Số tiền nợ không được để trống' })
  @IsNumber({}, { message: 'Số tiền nợ phải là số' })
  amount: number;

  @ApiProperty({
    description: 'Nội dung nhắc nợ',
    example: 'Tiền ăn trưa ngày 20/12',
  })
  @IsNotEmpty({ message: 'Nội dung nhắc nợ không được để trống' })
  @IsString()
  content: string;
}
