import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { Debt, DebtDocument } from '../models/debts/schemas/debt.schema';
import { CreateDebtDto } from './dto/create-debt.dto';
import { DebtSummaryDto, DebtDetailDto } from './dto/debt.dto';
import { CancelDebtDto } from './dto/cancel-debt.dto';
import { NotificationService } from '../notification/notification.service';

@Injectable()
export class DebtService {
  constructor(
    @InjectModel(Debt.name) private debtModel: Model<DebtDocument>,
    private jwtService: JwtService,
    private notificationService: NotificationService,
  ) {}

  private decodeToken(accessToken: string): string {
    try {
      const decoded = this.jwtService.decode(accessToken);
      //console.log(decoded);
      if (!decoded.sub) {
        throw new UnauthorizedException('Invalid token');
      }
      return decoded.sub;
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async createDebt(
    accessToken: string,
    createDebtDto: CreateDebtDto,
  ): Promise<Debt> {
    const fromUserId = this.decodeToken(accessToken);

    const newDebt = new this.debtModel({
      fromUserId,
      toUserId: createDebtDto.toUserId,
      amount: createDebtDto.amount,
      content: createDebtDto.content,
      status: 'pending',
    });

    return (await newDebt.save()).populate(['fromUserId', 'toUserId']);
  }

  async getDebtsByDebtor(accessToken: string): Promise<Debt[]> {
    const userId = this.decodeToken(accessToken);
    return this.debtModel
      .find({ toUserId: userId })
      .populate(['fromUserId', 'toUserId', 'transactionId'])
      .exec();
  }

  async getDebtsByCreditor(accessToken: string): Promise<Debt[]> {
    const userId = this.decodeToken(accessToken);

    return this.debtModel
      .find({ fromUserId: userId })
      .populate(['fromUserId', 'toUserId', 'transactionId'])
      .exec();
  }

  async getDebtsSummary(accessToken: string): Promise<DebtSummaryDto> {
    const userId = this.decodeToken(accessToken);

    // Lấy tất cả các khoản nợ liên quan đến user
    const [createdDebts, receivedDebts] = await Promise.all([
      this.debtModel
        .find({ fromUserId: userId })
        .populate(['fromUserId', 'toUserId'])
        .sort({ createdAt: -1 })
        .exec(),
      this.debtModel
        .find({ toUserId: userId })
        .populate(['fromUserId', 'toUserId'])
        .sort({ createdAt: -1 })
        .exec(),
    ]);

    // Tính tổng các khoản nợ
    const totalLent = createdDebts.reduce((sum, debt) => {
      return debt.status === 'pending' ? sum + debt.amount : sum;
    }, 0);

    const totalBorrowed = receivedDebts.reduce((sum, debt) => {
      return debt.status === 'pending' ? sum + debt.amount : sum;
    }, 0);

    // Map data sang DTO format
    const formatDebt = (debt: DebtDocument): DebtDetailDto => ({
      _id: debt._id.toString(),
      fromUser: {
        _id: debt.fromUserId._id.toString(),
        fullName: debt.fromUserId.fullName,
        username: debt.fromUserId.username,
      },
      toUser: {
        _id: debt.toUserId._id.toString(),
        fullName: debt.toUserId.fullName,
        username: debt.toUserId.username,
      },
      amount: debt.amount,
      content: debt.content,
      status: debt.status,
      createdAt: debt.createdAt,
    });

    return {
      totalLent,
      totalBorrowed,
      createdDebts: createdDebts.map(formatDebt),
      receivedDebts: receivedDebts.map(formatDebt),
    };
  }

  async cancelDebt(
    accessToken: string,
    debtId: string,
    cancelDebtDto: CancelDebtDto,
  ): Promise<Debt> {
    const userId = this.decodeToken(accessToken);
    const session = await this.debtModel.startSession();

    try {
      await session.startTransaction();

      // Tìm và lock document trong transaction
      const debt = await this.debtModel
        .findOneAndUpdate(
          {
            _id: debtId,
            status: 'pending', // Chỉ tìm những khoản nợ pending
            $or: [{ fromUserId: userId }, { toUserId: userId }],
          },
          { status: 'cancelled' },
          {
            new: true, // Trả về document sau khi update
            session,
            runValidators: true,
          },
        )
        .populate(['fromUserId', 'toUserId'])
        .exec();

      if (!debt) {
        throw new NotFoundException(
          'Không tìm thấy khoản nợ hoặc khoản nợ không thể hủy',
        );
      }

      // Gửi thông báo
      const isCancelledByCreator = debt.fromUserId._id.toString() === userId;
      const notifyUserId = isCancelledByCreator
        ? debt.toUserId._id.toString()
        : debt.fromUserId._id.toString();

      const notificationContent = isCancelledByCreator
        ? `Người tạo nợ ${debt.fromUserId.fullName} đã huỷ khoản nợ "${debt.content}" với lý do: ${cancelDebtDto.cancelReason}`
        : `Người nợ ${debt.toUserId.fullName} đã huỷ khoản nợ "${debt.content}" với lý do: ${cancelDebtDto.cancelReason}`;

      await this.notificationService.createNotification({
        userId: notifyUserId,
        content: notificationContent,
        type: 'DEBT_CANCELLED',
        relatedId: debt._id.toString(),
      });

      await session.commitTransaction();
      return debt;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
}
