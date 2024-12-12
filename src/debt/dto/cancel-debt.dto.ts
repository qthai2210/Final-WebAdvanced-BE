import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CancelDebtDto {
  @ApiProperty({
    description: 'Lý do huỷ nhắc nợ',
    example: 'Đã thanh toán bằng tiền mặt',
  })
  @IsNotEmpty()
  @IsString()
  cancelReason: string;
}
