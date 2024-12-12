import { Body, Controller, Get, Post, Param, Patch } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { DebtService } from './debt.service';
import { CreateDebtDto } from './dto/create-debt.dto';
import { BearerToken } from 'src/auth/decorators/auth.decorator';
import { DebtSummaryDto } from './dto/debt.dto';
import { CancelDebtDto } from './dto/cancel-debt.dto';

@ApiTags('Debts')
@Controller('debts')
@ApiBearerAuth()
export class DebtController {
  constructor(private readonly debtService: DebtService) {}

  @Post()
  @ApiOperation({ summary: 'Tạo một nhắc nợ mới' })
  @ApiResponse({
    status: 201,
    description: 'Nhắc nợ đã được tạo thành công.',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Người dùng chưa đăng nhập',
  })
  async createDebt(
    @BearerToken() accessToken: string,
    @Body() createDebtDto: CreateDebtDto,
  ) {
    return this.debtService.createDebt(accessToken, createDebtDto);
  }

  @Get('my-debts')
  @ApiOperation({
    summary: 'Lấy danh sách các khoản nợ mà người dùng hiện tại bị nhắc',
  })
  @ApiResponse({
    status: 200,
    description: 'Danh sách các khoản nợ được trả về thành công',
  })
  async getMyDebts(@BearerToken() accessToken: string) {
    return this.debtService.getDebtsByDebtor(accessToken);
  }

  @Get('created-debts')
  @ApiOperation({
    summary: 'Lấy danh sách các khoản nợ mà người dùng hiện tại đã tạo',
  })
  @ApiResponse({
    status: 200,
    description: 'Danh sách các khoản nợ đã tạo được trả về thành công',
  })
  async getCreatedDebts(@BearerToken() accessToken: string) {
    return this.debtService.getDebtsByCreditor(accessToken);
  }

  @Get('summary')
  @ApiOperation({
    summary: 'Lấy tổng hợp danh sách các khoản nợ',
  })
  @ApiResponse({
    status: 200,
    description: 'Danh sách nợ được trả về thành công',
    type: DebtSummaryDto,
  })
  async getDebtsSummary(@BearerToken() accessToken: string) {
    return this.debtService.getDebtsSummary(accessToken);
  }

  @Patch(':id/cancel')
  @ApiOperation({ summary: 'Huỷ một khoản nợ' })
  @ApiResponse({
    status: 200,
    description: 'Khoản nợ đã được huỷ thành công',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Không có quyền huỷ khoản nợ này',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - Không tìm thấy khoản nợ',
  })
  async cancelDebt(
    @BearerToken() accessToken: string,
    @Param('id') debtId: string,
    @Body() cancelDebtDto: CancelDebtDto,
  ) {
    return this.debtService.cancelDebt(accessToken, debtId, cancelDebtDto);
  }
}