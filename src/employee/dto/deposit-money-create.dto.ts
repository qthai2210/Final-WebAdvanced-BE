import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class DepositMoneyCreateDto {
  @ApiProperty({
    example: '2436521546',
    description: 'Receiver account number',
  })
  @IsString()
  accountNumber: string;

  @ApiProperty({
    example: 'johndoe',
    description: 'Username',
  })
  @IsString()
  username: string;

  @ApiProperty({
    example: '10000',
    description: 'The amount to deposit into account',
  })
  @IsNotEmpty()
  amount: number;
}
