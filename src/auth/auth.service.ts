import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User, UserDocument, UserStatus } from './schemas/user.schema';
import {
  ChangePasswordDto,
  RegisterDto,
  RegisterWithoutPasswordDto,
} from './dto/auth.dto';

import { AuthData } from './interfaces/auth.interface';
import { MailService } from 'src/mail/mail.service';
import { AccountsService } from 'src/accounts/accounts.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private mailService: MailService,
    private accountsService: AccountsService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthData> {
    try {
      const existingUser = await this.userModel
        .findOne({
          $or: [
            { username: registerDto.username },
            { email: registerDto.email },
            { phone: registerDto.phone },
          ],
        })
        .exec();

      if (existingUser) {
        throw new ConflictException(
          'Username, email or phone number already exists',
        );
      }

      const hashedPassword = await bcrypt.hash(registerDto.password, 10);

      // Create user document using plain object
      const newUser = await this.userModel.create({
        ...registerDto,
        password: hashedPassword,
        status: UserStatus.PENDING,
        failedLoginAttempts: 0,
      });

      // Ensure the document is properly saved and populated
      const savedUser = await newUser.save();
      console.log('Created user document:', savedUser.toJSON());

      return this.generateToken(savedUser);
    } catch (error) {
      console.error('Registration error details:', {
        error: error.message,
        stack: error.stack,
        name: error.name,
        fullError: error,
      });

      if (error.name === 'MongooseError') {
        throw new BadRequestException(`Database error: ${error.message}`);
      }
      throw error;
    }
  }

  async login(username: string, password: string): Promise<AuthData> {
    const user = await this.userModel.findOne({ username }).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.isLocked()) {
      throw new UnauthorizedException(
        'Account is locked. Please try again later.',
      );
    }

    if (user.status === UserStatus.LOCKED) {
      throw new UnauthorizedException(
        'Account is permanently locked. Please contact support.',
      );
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      user.failedLoginAttempts += 1;
      await user.save();
      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset failed attempts on successful login
    user.failedLoginAttempts = 0;
    user.lastLoginAt = new Date();
    await user.save();

    return this.generateToken(user);
  }

  private generateToken(user: UserDocument): AuthData {
    const accessTokenPayload = {
      sub: user._id,
      username: user.username,
      role: user.role,
      status: user.status,
      type: 'access_token',
    };

    const refreshTokenPayload = {
      sub: user._id,
      type: 'refresh_token',
    };

    return {
      access_token: this.jwtService.sign(accessTokenPayload, {
        expiresIn: '15m',
      }),
      refresh_token: this.jwtService.sign(refreshTokenPayload, {
        expiresIn: '7d',
      }),
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        role: user.role,
        status: user.status,
        fullName: user.fullName,
      },
    };
  }

  async refreshToken(refreshToken: string): Promise<AuthData> {
    try {
      const payload = this.jwtService.verify(refreshToken);

      if (payload.type !== 'refresh_token') {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.userModel.findById(payload.sub).exec();
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return this.generateToken(user);
    } catch (error) {
      console.error(error);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async verifyAccessToken(accessToken: string): Promise<{
    isValid: boolean;
    isExpired: boolean;
    message?: string;
  }> {
    try {
      const payload = this.jwtService.verify(accessToken);
      if (payload.type !== 'access_token') {
        return {
          isValid: false,
          isExpired: false,
          message: 'Invalid token type',
        };
      }

      const user = await this.userModel.findById(payload.sub).exec();
      if (!user) {
        return { isValid: false, isExpired: false, message: 'User not found' };
      }

      return { isValid: true, isExpired: false };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return {
          isValid: false,
          isExpired: true,
          message: 'Token has expired',
        };
      }
      return { isValid: false, isExpired: false, message: 'Invalid token' };
    }
  }

  async reLoginWithToken(accessToken: string): Promise<AuthData> {
    try {
      const payload = this.jwtService.verify(accessToken);

      if (payload.type !== 'access_token') {
        throw new UnauthorizedException('Invalid token type');
      }

      const user = await this.userModel.findById(payload.sub).exec();
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (user.isLocked() || user.status === UserStatus.LOCKED) {
        throw new UnauthorizedException('Account is locked');
      }

      // Update last login time
      user.lastLoginAt = new Date();
      await user.save();

      return this.generateToken(user);
    } catch (error) {
      console.error(error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async changePassword(
    accessToken: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<boolean> {
    const payload = this.jwtService.verify(accessToken);
    console.log('Payload:', payload);
    const user = await this.userModel.findById(payload.sub).exec();
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(
      changePasswordDto.currentPassword,
      user.password,
    );
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Verify new password matches confirmation
    if (changePasswordDto.newPassword !== changePasswordDto.confirmPassword) {
      throw new BadRequestException(
        'New password and confirmation do not match',
      );
    }

    // Hash and save new password
    const hashedPassword = await bcrypt.hash(changePasswordDto.newPassword, 12);
    user.password = hashedPassword;
    await user.save();

    return true;
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      // Return success even if user not found to prevent email enumeration
      return { message: 'If the email exists, a reset OTP will be sent' };
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 15); // OTP valid for 15 minutes

    // Save OTP and expiry to user
    user.resetPasswordOTP = otp;
    user.resetPasswordOTPExpires = otpExpiry;
    await user.save();

    // Replace mailerService with mailService
    await this.mailService.sendPasswordResetEmail(email, otp);

    return { message: 'Reset OTP has been sent to your email' };
  }

  async resetPassword(
    email: string,
    otp: string,
    newPassword: string,
    confirmPassword: string,
  ): Promise<{ message: string }> {
    if (newPassword !== confirmPassword) {
      throw new BadRequestException(
        'New password and confirmation do not match',
      );
    }

    const user = await this.userModel
      .findOne({
        email,
        resetPasswordOTP: otp,
        resetPasswordOTPExpires: { $gt: new Date() },
      })
      .exec();

    if (!user) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update user password and clear OTP fields
    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpires = undefined;
    await user.save();

    return { message: 'Password reset successful' };
  }

  async initiateForgotPassword(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      // Return void to prevent email enumeration
      return;
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 15); // OTP valid for 15 minutes

    user.resetPasswordOTP = otp;
    user.resetPasswordOTPExpires = otpExpiry;
    await user.save();

    // Replace mailerService with mailService
    await this.mailService.sendPasswordResetEmail(email, otp);
  }

  async resetPasswordWithOTP(
    email: string,
    otp: string,
    newPassword: string,
  ): Promise<boolean> {
    const user = await this.userModel
      .findOne({
        email,
        resetPasswordOTP: otp,
        resetPasswordOTPExpires: { $gt: new Date() },
      })
      .exec();

    if (!user) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpires = undefined;
    await user.save();

    return true;
  }

  async registerWithOtpVerification(
    registerDto: RegisterWithoutPasswordDto,
  ): Promise<boolean> {
    try {
      const existingUser = await this.userModel
        .findOne({
          $or: [
            { username: registerDto.username },
            { email: registerDto.email },
            { phone: registerDto.phone },
          ],
        })
        .exec();

      if (existingUser) {
        throw new ConflictException(
          'Username, email or phone number already exists',
        );
      }

      const tempPassword = '123456';
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      // Create user document using plain object
      const newUser = await this.userModel.create({
        ...registerDto,
        password: hashedPassword,
        status: UserStatus.PENDING,
        failedLoginAttempts: 0,
        isLocked: () => true,
      });

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiry = new Date();
      otpExpiry.setMinutes(otpExpiry.getMinutes() + 15); // OTP valid for 15 minutes

      // Save OTP and expiry to user
      newUser.resetPasswordOTP = otp;
      newUser.resetPasswordOTPExpires = otpExpiry;
      const authData = this.generateToken(newUser);
      newUser.refreshToken = authData.refresh_token;
      await newUser.save();

      const isOtpSent = await this.mailService.sendOtpToVerifyUserAccount(
        newUser.email,
        otp,
      );

      if (isOtpSent) return true;
      else return false;
    } catch (error) {
      console.error('Registration error details:', {
        error: error.message,
        stack: error.stack,
        name: error.name,
        fullError: error,
      });

      if (error.name === 'MongooseError') {
        throw new BadRequestException(`Database error: ${error.message}`);
      }
      throw error;
    }
  }

  async verifyRegisterOtp(email: string, otp: string) {
    const isOtpVerified = await this.mailService.verifyOtp(email, otp);
    if (isOtpVerified) {
      const existingUser = await this.userModel
        .findOne({
          $or: [{ email: email }],
        })
        .exec();

      existingUser.isLocked = () => false;

      const characters =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      const passwordLength = 8;
      let password = '';

      for (let i = 0; i < passwordLength; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        password += characters[randomIndex];
      }
      existingUser.password = await bcrypt.hash(password, 10);
      await this.mailService.sendPasswordUserAccount(email, password);
      await existingUser.save();
      const authData = await this.refreshToken(existingUser.refreshToken);
      const newPaymentAccount = await this.accountsService.createOne(
        authData.access_token,
      );

      if (newPaymentAccount) return true;
      else return false;
    }
  }
}
