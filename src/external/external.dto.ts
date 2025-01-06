import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class ExternalTransferReceiveDto {
  @ApiProperty({
    example: 'BANK_A',
    description: 'Partner bank code',
  })
  @IsString()
  @IsNotEmpty()
  partnerCode: string;

  @ApiProperty({
    description: 'Encoded transaction data including signature and hash',
  })
  @IsString()
  @IsNotEmpty()
  transferData: string;
}
