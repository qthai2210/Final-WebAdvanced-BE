import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class CancelDebtDto {
  @ApiProperty({ description: 'ID of the debt to cancel' })
  @IsString()
  @IsNotEmpty()
  debtId: string;

  @ApiProperty({ description: 'Reason for cancelling the debt' })
  @IsString()
  @IsNotEmpty()
  cancelReason: string;
}
