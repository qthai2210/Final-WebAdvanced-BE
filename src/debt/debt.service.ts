import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { Debt, DebtDocument } from '../models/debts/schemas/debt.schema';
import { CreateDebtDto } from './dto/create-debt.dto';
import {
  DebtSummaryDto,
  DebtDetailDto,
  PayDebtDto,
  SendPaymentOtpDto,
} from './dto/debt.dto';
import { CancelDebtDto } from './dto/cancel-debt.dto';
import { NotificationService } from '../notification/notification.service';
import { User } from '../auth/schemas/user.schema'; // Thêm import này
import { JwtUtil } from 'src/utils/jwt.util';
import { MailService } from '../mail/mail.service'; // Thêm import này
import { AuthService } from 'src/auth/auth.service';

@Injectable()
export class DebtService {
  constructor(
    @InjectModel(Debt.name) private debtModel: Model<DebtDocument>,
    @InjectModel(User.name) private userModel: Model<User>, // Thêm inject UserModel
    private jwtService: JwtService,
    private notificationService: NotificationService,
    private mailService: MailService,
    private JWTUtil: JwtUtil,
    private authService: AuthService, // Thêm authService
  ) {}

  private decodeToken(accessToken: string) {
    try {
      const decoded = this.JWTUtil.decodeJwt(accessToken);
      console.log(decoded);
      if (!decoded.sub) {
        throw new UnauthorizedException('Invalid token');
      }
      return decoded;
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async createDebt(
    accessToken: string,
    createDebtDto: CreateDebtDto,
  ): Promise<Debt> {
    const user = this.decodeToken(accessToken);

    const newDebt = new this.debtModel({
      fromUserId: user.sub,
      //toUserId: createDebtDto.toUserId,
      amount: createDebtDto.amount,
      content: createDebtDto.content,
      status: 'pending',
    });
    console.log(newDebt);
    return (await newDebt.save()).populate(['fromUserId', 'toUserId']);
  }

  async getDebtsByDebtor(accessToken: string): Promise<Debt[]> {
    const user = this.decodeToken(accessToken);
    return this.debtModel
      .find({ toUserId: user.sub })
      .populate(['fromUserId', 'toUserId', 'transactionId'])
      .exec();
  }

  async getDebtsByCreditor(accessToken: string): Promise<Debt[]> {
    const user = this.decodeToken(accessToken);

    return this.debtModel
      .find({ fromUserId: user.sub })
      .populate(['fromUserId', 'toUserId', 'transactionId'])
      .exec();
  }

  async getDebtsSummary(accessToken: string): Promise<DebtSummaryDto> {
    const user = this.decodeToken(accessToken);

    // Lấy tất cả các khoản nợ liên quan đến user
    const [createdDebts, receivedDebts] = await Promise.all([
      this.debtModel
        .find({ fromUserId: user.sub })
        .populate(['fromUserId', 'toUserId'])
        .sort({ createdAt: -1 })
        .exec(),
      this.debtModel
        .find({ toUserId: user.sub })
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
        _id: debt.fromUserId.toString(),
        fullName: debt.fromUserId.fullName,
        username: debt.fromUserId.username,
      },
      toUser: {
        _id: debt.toUserId.toString(),
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
    const user = this.decodeToken(accessToken);
    const session = await this.debtModel.startSession();

    try {
      await session.startTransaction();

      // Tìm và lock document trong transaction
      const debt = await this.debtModel
        .findOneAndUpdate(
          {
            _id: debtId,
            status: 'pending', // Chỉ tìm những khoản nợ pending
            $or: [{ fromUserId: user.sub }, { toUserId: user.sub }],
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
      const isCancelledByCreator =
        debt.fromUserId.toString() === user.sub.toString();
      const notifyUserId = isCancelledByCreator
        ? debt.toUserId.toString()
        : debt.fromUserId.toString();

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

  async payDebt(accessToken: string, payDebtDto: PayDebtDto) {
    const decoded = this.decodeToken(accessToken);

    // Lấy thông tin user đầy đủ từ database
    const user = await this.userModel.findById(decoded.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const debt = await this.debtModel.findById(payDebtDto.debtId);
    if (!debt) {
      throw new NotFoundException('Debt not found');
    }

    if (debt.status === 'paid') {
      throw new BadRequestException('Debt already paid');
    }

    if (debt.toUserId.toString() !== user._id.toString()) {
      throw new BadRequestException('You are not the debtor');
    }

    // Verify OTP với mailService thay vì authService
    const isValidOtp = await this.mailService.verifyOtp(
      user.email,
      payDebtDto.otp,
    );

    if (!isValidOtp) {
      throw new BadRequestException('Invalid OTP');
    }

    // Process payment
    const updatedDebt = await this.debtModel.findByIdAndUpdate(
      payDebtDto.debtId,
      { status: 'paid', paidAt: new Date() },
      { new: true },
    );

    // Send notification to debt creator
    await this.notificationService.createNotification({
      userId: debt.fromUserId.toString(),
      content: `Your debt of ${debt.amount} has been paid`,
      type: 'DEBT_PAYMENT',
      relatedId: debt._id.toString(),
    });

    return updatedDebt;
  }

  async sendPaymentOtp(accessToken: string, sendOtpDto: SendPaymentOtpDto) {
    const decoded = this.decodeToken(accessToken);

    // Lấy thông tin user đầy đủ từ database
    const user = await this.userModel.findById(decoded.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const debt = await this.debtModel.findById(sendOtpDto.debtId);
    if (!debt) {
      throw new NotFoundException('Debt not found');
    }

    if (debt.status !== 'pending') {
      throw new BadRequestException('Debt is not in pending status');
    }

    if (debt.toUserId.toString() !== user._id.toString()) {
      throw new BadRequestException('You are not the debtor');
    }

    // Gửi OTP với email từ user object
    await this.authService.initiateForgotPassword(user.email);

    return {
      message: 'OTP has been sent to your email',
    };
  }
}
