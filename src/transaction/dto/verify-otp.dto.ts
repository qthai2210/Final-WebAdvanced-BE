import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEnum } from 'class-validator';

export class VerifyOtpTransactionDto {
  @ApiProperty({ example: '123456', description: 'OTP code' })
  @IsString()
  @IsNotEmpty()
  otp: string;

  @ApiProperty({
    example: '507f1f77bcf86cd799439011',
    description: 'Transaction ID',
  })
  @IsString()
  @IsNotEmpty()
  transactionId: string;

  @ApiProperty({
    example: 'internal',
    description: 'Transaction type',
    enum: ['internal', 'external'],
  })
  @IsEnum(['internal', 'external'])
  type: 'internal' | 'external';
}
