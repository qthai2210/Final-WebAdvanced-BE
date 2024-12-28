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
import { Account } from '../models/accounts/schemas/account.schema';
import { Transaction } from '../models/transactions/schemas/transaction.schema';

@Injectable()
export class DebtService {
  private readonly MAX_RETRIES = 3;
  private readonly RETRY_DELAY = 1000; // 1 second

  constructor(
    @InjectModel(Debt.name) private debtModel: Model<DebtDocument>,
    @InjectModel(User.name) private userModel: Model<User>, // Thêm inject UserModel
    private jwtService: JwtService,
    private notificationService: NotificationService,
    private mailService: MailService,
    private JWTUtil: JwtUtil,
    private authService: AuthService, // Thêm authService
    @InjectModel(Account.name) private accountModel: Model<Account>,
    @InjectModel(Transaction.name) private transactionModel: Model<Transaction>,
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

  private async retry<T>(
    operation: () => Promise<T>,
    retries = this.MAX_RETRIES,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (
        retries > 0 &&
        (error.message.includes('Write conflict') ||
          error.message.includes('Transaction has been aborted'))
      ) {
        await new Promise((resolve) => setTimeout(resolve, this.RETRY_DELAY));
        return this.retry(operation, retries - 1);
      }
      throw error;
    }
  }

  async createDebt(
    accessToken: string,
    createDebtDto: CreateDebtDto,
  ): Promise<Debt> {
    const user = this.decodeToken(accessToken);

    if (user.sub === createDebtDto.accountNumber) {
      throw new BadRequestException('Cannot create debt to oneself');
    }

    const account = await this.accountModel.findOne({
      accountNumber: createDebtDto.accountNumber,
    });

    if (!account) {
      throw new NotFoundException('Account not found');
    }

    const toUserId = await this.userModel.findById(account.userId);

    if (!toUserId) {
      throw new NotFoundException('User not found');
    }

    const newDebt = new this.debtModel({
      fromUserId: user.sub,
      toUserId: toUserId._id,
      amount: createDebtDto.amount,
      content: createDebtDto.content,
      status: 'pending',
    });

    const savedDebt = await newDebt.save();

    await this.notificationService.createNotification({
      userId: toUserId._id.toString(),
      content: `You have a new debt of ${createDebtDto.amount} from ${user.username}`,
      type: 'DEBT_CREATED',
      relatedId: savedDebt._id.toString(),
    });

    return (await savedDebt.populate('fromUserId', '_id fullName')).populate(
      'toUserId',
      '_id fullName',
    );
  }

  async getDebtsByDebtor(accessToken: string): Promise<Debt[]> {
    const user = this.decodeToken(accessToken);
    return this.debtModel
      .find({ toUserId: user.sub })
      .populate('fromUserId', '_id fullName')
      .populate('toUserId', '_id fullName')
      .lean()
      .exec() as unknown as Debt[];
  }

  async getDebtsByCreditor(accessToken: string): Promise<Debt[]> {
    const user = this.decodeToken(accessToken);
    return this.debtModel
      .find({ fromUserId: user.sub })
      .populate('fromUserId', '_id fullName')
      .populate('toUserId', '_id fullName')
      .lean()
      .exec() as unknown as Debt[];
  }

  async getDebtsSummary(accessToken: string): Promise<DebtSummaryDto> {
    const user = this.decodeToken(accessToken);

    // Lấy tất cả các khoản nợ liên quan đến user
    const [createdDebts, receivedDebts] = await Promise.all([
      this.debtModel
        .find({ fromUserId: user.sub })
        .populate('fromUserId', '_id fullName')
        .populate('toUserId', '_id fullName')
        .sort({ createdAt: -1 })
        .exec(),
      this.debtModel
        .find({ toUserId: user.sub })
        .populate('fromUserId', '_id fullName')
        .populate('toUserId', '_id fullName')
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
    cancelDebtDto: CancelDebtDto,
  ): Promise<Debt> {
    const user = this.decodeToken(accessToken);
    const session = await this.debtModel.startSession();

    try {
      await session.startTransaction();

      const debt = await this.debtModel
        .findOneAndUpdate(
          {
            _id: cancelDebtDto.debtId,
            status: 'pending',
            $or: [{ fromUserId: user.sub }, { toUserId: user.sub }],
          },
          { status: 'cancelled' },
          {
            new: true,
            session,
            runValidators: true,
          },
        )
        .populate('fromUserId', '_id fullName')
        .populate('toUserId', '_id fullName')
        .exec();

      if (!debt) {
        throw new NotFoundException('Debt not found or cannot be cancelled');
      }

      // Fix: Properly extract IDs from populated fields
      const fromUserId = (debt.fromUserId as any)._id
        ? (debt.fromUserId as any)._id.toString()
        : debt.fromUserId.toString();
      const toUserId = (debt.toUserId as any)._id
        ? (debt.toUserId as any)._id.toString()
        : debt.toUserId.toString();

      const isCancelledByCreator = fromUserId === user.sub;
      const notifyUserId = isCancelledByCreator ? toUserId : fromUserId;

      const fromUserName = debt.fromUserId.fullName || 'Unknown';
      const toUserName = debt.toUserId.fullName || 'Unknown';

      const notificationContent = isCancelledByCreator
        ? `Debt creator ${fromUserName} cancelled the debt "${debt.content}" with reason: ${cancelDebtDto.cancelReason}`
        : `Debtor ${toUserName} cancelled the debt "${debt.content}" with reason: ${cancelDebtDto.cancelReason}`;

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
    return this.retry(async () => {
      let session;
      try {
        session = await this.debtModel.db.startSession();

        // First verify OTP outside the transaction
        const isValidOtp = await this.mailService.verifyDebtPaymentOtp(
          payDebtDto.debtId,
          payDebtDto.otp,
        );

        if (!isValidOtp) {
          throw new BadRequestException('Invalid or expired OTP');
        }

        const transaction = await session.withTransaction(async () => {
          const decoded = this.decodeToken(accessToken);
          const user = await this.userModel.findById(decoded.sub);
          if (!user) throw new UnauthorizedException('User not found');

          // Find and lock the debt document
          const debt = await this.debtModel
            .findOne({
              _id: payDebtDto.debtId,
              status: 'pending',
            })
            .populate('fromUserId', '_id fullName')
            .populate('toUserId', '_id fullName')
            .session(session);

          if (!debt) {
            throw new NotFoundException('Debt not found or already processed');
          }

          // Don't verify OTP again here

          // Get and lock the accounts
          const [debtorAccount, creditorAccount] = await Promise.all([
            this.accountModel
              .findOne({ userId: debt.toUserId, type: 'payment' })
              .session(session),
            this.accountModel
              .findOne({ userId: debt.fromUserId, type: 'payment' })
              .session(session),
          ]);

          if (!debtorAccount || !creditorAccount)
            throw new BadRequestException('Payment accounts not found');

          if (debtorAccount.balance < debt.amount)
            throw new BadRequestException('Insufficient balance');

          const transaction = new this.transactionModel({
            fromAccount: debtorAccount.accountNumber,
            toAccount: creditorAccount.accountNumber,
            amount: debt.amount,
            type: 'debt_payment',
            status: 'completed',
            content: `Payment for debt: ${debt.content}`,
            fee: 0,
            feeType: 'sender',
          });

          // Execute all updates within the transaction
          await Promise.all([
            this.accountModel.findByIdAndUpdate(
              debtorAccount._id,
              { $inc: { balance: -debt.amount } },
              { session, new: true },
            ),
            this.accountModel.findByIdAndUpdate(
              creditorAccount._id,
              { $inc: { balance: debt.amount } },
              { session, new: true },
            ),
            transaction.save({ session }),
            this.debtModel.findByIdAndUpdate(
              debt._id,
              {
                status: 'paid',
                paidAt: new Date(),
                transactionId: transaction._id,
              },
              { session, new: true },
            ),
          ]);

          // Return both transaction and debt for notification
          return { transaction, debt };
        });

        // Create notification with proper details
        if (transaction?.debt) {
          await this.notificationService.createNotification({
            userId: transaction.debt.fromUserId._id.toString(), // Send to creditor
            content: `Debt payment of ${transaction.debt.amount} VND received from ${transaction.debt.toUserId.fullName} for "${transaction.debt.content}"`,
            type: 'DEBT_PAYMENT',
            relatedId: transaction.debt._id.toString(),
          });
        }

        return transaction.transaction;
      } finally {
        if (session) {
          await session.endSession();
        }
      }
    });
  }

  async sendPaymentOtp(accessToken: string, sendOtpDto: SendPaymentOtpDto) {
    const decoded = this.decodeToken(accessToken);
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
    // console.log('abcdefg');
    // console.log(debt.toUserId.toString(), user._id.toString());
    // if (debt.toUserId.toString() !== user._id.toString()) {
    //   throw new BadRequestException('You are not the debtor');
    // }

    await this.mailService.sendOtpToVerifyDebtPayment(
      user.email,
      debt._id.toString(),
      debt.amount,
    );

    return {
      message: 'OTP has been sent to your email',
    };
  }
}
