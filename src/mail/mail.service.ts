import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../auth/schemas/user.schema';

@Injectable()
export class MailService {
  constructor(
    private mailerService: MailerService,
    @InjectModel(User.name) private userModel: Model<User>,
  ) { }

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

  async sendOtpToVerifyUserAccount(email: string, otp: string): Promise<boolean> {
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

  async sendPasswordUserAccount(email: string, password: string): Promise<boolean> {
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
}