import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsDateString, IsString } from 'class-validator';
import { PaginationDto } from 'src/auth/dto/pagination.dto';

export class ReconciliationQueryDto extends PaginationDto {
  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  toDate?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  bankId?: string;
}
