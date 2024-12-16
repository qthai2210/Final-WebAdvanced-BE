import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, Length } from 'class-validator';

export class RecipientDto {
  @ApiProperty({
    description: 'Account number of recipient',
    example: '9666048417',
  })
  @IsString()
  @Length(10, 10)
  accountNumber: string;

  @ApiProperty({
    description: 'Nickname of recipient',
    example: 'Joe',
  })
  @IsString()
  @IsOptional()
  nickname: string;
}
