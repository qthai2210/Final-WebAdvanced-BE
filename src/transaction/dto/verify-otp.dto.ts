import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Length } from 'class-validator';

export class VerifyOtpDto {
  @ApiProperty({ example: '123456', description: 'OTP code' })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;

  @ApiProperty({
    example: '507f1f77bcf86cd799439011',
    description: 'Transaction ID',
  })
  @IsString()
  @IsNotEmpty()
  transactionId: string;
}
