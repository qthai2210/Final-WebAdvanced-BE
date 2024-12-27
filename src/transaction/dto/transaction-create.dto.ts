import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsNumber, Min, IsEnum } from 'class-validator';

export class InternalTransferDto {
  @ApiProperty({
    example: '2436521546',
    description: 'Receiver account number',
  })
  @IsString()
  @IsNotEmpty()
  toAccount: string;

  @ApiProperty({ example: 1000000, description: 'Transfer amount' })
  @IsNumber()
  @Min(1)
  amount: number;

  @ApiProperty({
    example: 'Payment for services',
    description: 'Transfer content',
  })
  @IsString()
  @IsNotEmpty()
  content: string;

  @ApiProperty({
    example: 'sender',
    description: 'Fee payer',
    enum: ['sender', 'receiver'],
  })
  @IsEnum(['sender', 'receiver'])
  feeType: 'sender' | 'receiver';
}

export class ExternalTransferDto {
  @ApiProperty({
    example: '2436521546',
    description: 'Receiver account number',
  })
  @IsString()
  @IsNotEmpty()
  toAccount: string;

  @ApiProperty({
    example: '123',
    description: 'Bank ID from the banks table',
  })
  @IsString()
  @IsNotEmpty()
  bankId: string;

  @ApiProperty({ example: 1000000, description: 'Transfer amount' })
  @IsNumber()
  @Min(1)
  amount: number;

  @ApiProperty({
    example: 'Payment for services',
    description: 'Transfer content',
  })
  @IsString()
  @IsNotEmpty()
  content: string;

  @ApiProperty({
    example: 'sender',
    description: 'Fee payer',
    enum: ['sender', 'receiver'],
  })
  @IsEnum(['sender', 'receiver'])
  feeType: 'sender' | 'receiver';
}

export class ExternalTransferReceiveDto {
  @ApiProperty({
    example: '2436521546',
    description: 'Receiver account number in our bank',
  })
  @IsString()
  @IsNotEmpty()
  toAccount: string;

  @ApiProperty({ example: 1000000, description: 'Transfer amount' })
  @IsNumber()
  @Min(1)
  amount: number;

  @ApiProperty({
    example: 'Payment for services',
    description: 'Transfer content',
  })
  @IsString()
  @IsNotEmpty()
  content: string;

  @ApiProperty({
    example: '123',
    description: 'Source bank ID',
  })
  @IsString()
  @IsNotEmpty()
  sourceBankId: string;

  @ApiProperty({
    example: 'TRANS123',
    description: 'Original transaction ID from source bank',
  })
  @IsString()
  @IsNotEmpty()
  sourceTransactionId: string;
}
