import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../auth/schemas/user.schema';
import { Transaction } from 'src/models/transactions/schemas/transaction.schema';
import { Debt } from 'src/models/debts/schemas/debt.schema';

@Injectable()
export class MailService {
  constructor(
    private mailerService: MailerService,
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(Transaction.name) private transactionModel: Model<Transaction>,
    @InjectModel(Debt.name) private debtModel: Model<any>,
  ) {}

  async sendUserConfirmation(user: User, token: string) {
    const url = `example.com/auth/confirm?token=${token}`;

    await this.mailerService.sendMail({
      to: user.email,
      // from: '"Support Team" <support@example.com>', // override default from
      subject: 'Welcome to Nice App! Confirm your Email',
      template: './confirmation', // `.hbs` extension is appended automatically
      context: {
        // ✏️ filling curly brackets with content
        name: user.username,
        url,
      },
    });
  }

  async sendPasswordResetEmail(email: string, otp: string): Promise<void> {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <h3>Password Reset Request</h3>
        <p>Your OTP for password reset is: <strong>${otp}</strong></p>
        <p>This OTP will expire in 15 minutes.</p>
        <p>If you did not request this password reset, please ignore this email.</p>
      `,
    });
  }

  async verifyOtp(email: string, otp: string): Promise<boolean> {
    const user = await this.userModel.findOne({
      email,
      resetPasswordOTP: otp,
      resetPasswordOTPExpires: { $gt: new Date() },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    return true;
  }

  async sendOtpToVerifyUserAccount(
    email: string,
    otp: string,
  ): Promise<boolean> {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Verify User Account OTP',
        html: `
          <h3>Verify User Account Request</h3>
          <p>Your OTP for verify user account is: <strong>${otp}</strong></p>
          <p>This OTP will expire in 15 minutes.</p>
          <p>If you did not request this password reset, please ignore this email.</p>
        `,
      });
      return true;
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  async sendPasswordUserAccount(
    email: string,
    password: string,
  ): Promise<boolean> {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'User Account Password',
        html: `
          <h3>User Account Password</h3>
          <p>This is the password for your account: <strong>${password}</strong></p>
        `,
      });
      return true;
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  async sendOtpToVerifyTransaction(
    email: string,
    transactionId: string,
  ): Promise<void> {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 15); // OTP valid for 15 minutes

    await this.transactionModel.findByIdAndUpdate(transactionId, {
      otp: otp,
      otpExpired: otpExpiry,
    });

    await this.mailerService.sendMail({
      to: email,
      subject: 'OTP for Transaction Verification',
      html: `
        <h3>Transaction Verification</h3>
        <p>Your OTP for transaction verification is: <strong>${otp}</strong></p>
        <p>This OTP will expire in 15 minutes.</p>
        <p>If you did not initiate this transaction, please contact support immediately.</p>
      `,
    });
  }

  async verifyOtpTransaction(
    transactionId: string,
    otp: string,
  ): Promise<boolean> {
    const transaction = await this.transactionModel.findOne({
      _id: transactionId,
      otp,
      otpExpired: { $gt: new Date() },
    });

    if (!transaction) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    return true;
  }

  async sendOtpToVerifyDebtPayment(
    email: string,
    debtId: string,
    amount: number,
  ): Promise<void> {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 15);

    // Update with error handling and verification
    const result = await this.debtModel.findByIdAndUpdate(
      debtId,
      {
        $set: {
          otp: otp,
          otpExpired: otpExpiry,
        },
      },
      { new: true },
    );

    console.log('Updated debt with OTP:', {
      debtId,
      otp,
      otpExpiry,
      success: !!result,
    });

    if (!result) {
      throw new Error('Failed to save OTP to debt record');
    }

    await this.mailerService.sendMail({
      to: email,
      subject: 'OTP for Debt Payment Verification',
      html: `
        <h3>Debt Payment Verification</h3>
        <p>Your OTP for debt payment verification is: <strong>${otp}</strong></p>
        <p>Amount to be paid: ${amount}</p>
        <p>This OTP will expire in 15 minutes.</p>
        <p>If you did not initiate this payment, please contact support immediately.</p>
      `,
    });
  }

  async verifyDebtPaymentOtp(debtId: string, otp: string): Promise<boolean> {
    console.log('Verifying OTP:', { debtId, otp });

    const debt = await this.debtModel.findOneAndUpdate(
      {
        _id: debtId,
        otp: otp,
        otpExpired: { $gt: new Date() },
        status: 'pending',
      },
      {
        $unset: { otp: '', otpExpired: '' },
      },
      {
        new: false, // Return the document before update
        select: '+otp +otpExpired',
      },
    );

    console.log('Verification result:', {
      exists: !!debt,
      otp: debt?.otp,
      expiry: debt?.otpExpired,
    });

    return !!debt;
  }

  async sendAccountLockedEmail(email: string): Promise<void> {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Account Locked Notification',
      html: `
        <h1>Account Locked</h1>
        <p>Your account has been locked for security reasons.</p>
        <p>If you did not request this action, please contact our support team immediately.</p>
        <p>If you want to unlock your account, please log in and request an unlock code.</p>
      `,
    });
  }

  async sendUnlockAccountOtp(email: string, otp: string): Promise<void> {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Account Unlock OTP',
      html: `
        <h1>Account Unlock Verification</h1>
        <p>Your OTP code to unlock your account is: <strong>${otp}</strong></p>
        <p>This code will expire in 15 minutes.</p>
        <p>If you did not request to unlock your account, please ignore this email.</p>
      `,
    });
  }

  async sendAccountUnlockedEmail(email: string): Promise<void> {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Account Unlocked Successfully',
      html: `
        <h1>Account Unlocked</h1>
        <p>Your account has been successfully unlocked.</p>
        <p>You can now log in to your account normally.</p>
        <p>If you did not request this action, please contact our support team immediately.</p>
      `,
    });
  }
}
