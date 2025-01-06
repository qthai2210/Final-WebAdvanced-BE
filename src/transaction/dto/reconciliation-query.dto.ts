import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsDateString, IsString } from 'class-validator';

export class ReconciliationQueryDto {
  @ApiProperty({ required: true })
  @IsDateString()
  fromDate: string;

  @ApiProperty({ required: true })
  @IsDateString()
  toDate: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  bankId?: string; // Specific bank or all banks if not provided
}
