import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  HttpException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import {
  User,
  UserDocument,
  UserStatus,
  UserRole,
} from './schemas/user.schema';
import {
  ChangePasswordDto,
  RegisterDto,
  RegisterWithoutPasswordDto,
} from './dto/auth.dto';
import axios from 'axios';
import { AuthData } from './interfaces/auth.interface';
import { MailService } from 'src/mail/mail.service';
import { AccountsService } from 'src/accounts/accounts.service';
import { PaginatedResponse } from './dto/pagination.dto';
import { EmployeeFilterDto } from './dto/employee-filter.dto';

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

  async loginWithRecaptcha(
    username: string,
    password: string,
    recaptchaToken: string,
  ): Promise<AuthData> {
    // Verify recaptcha first
    const isValidRecaptcha = await this.verifyRecaptcha(recaptchaToken);
    if (!isValidRecaptcha) {
      throw new UnauthorizedException('Invalid recaptcha');
    }

    // Proceed with base login
    return this.baseLogin(username, password);
  }

  async login(username: string, password: string): Promise<AuthData> {
    return this.baseLogin(username, password);
  }

  private async baseLogin(
    username: string,
    password: string,
  ): Promise<AuthData> {
    const user = await this.validateUser(username, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status === UserStatus.LOCKED) {
      throw new UnauthorizedException('Account is locked');
    }

    return this.generateToken(user);
  }

  private async verifyRecaptcha(token: string): Promise<boolean> {
    try {
      const response = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify`,
        null,
        {
          params: {
            secret: process.env.RECAPTCHA_SECRET_KEY,
            response: token,
          },
        },
      );

      return response.data.success;
    } catch (error) {
      console.error(error);
      throw new HttpException(
        'Error verifying reCAPTCHA',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  private async validateUser(
    username: string,
    password: string,
  ): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ username }).exec();
    if (!user) {
      return null;
    }

    if (user.checkLocked()) {
      throw new UnauthorizedException('Account is locked');
    }

    try {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        // Increment failed attempts
        user.failedLoginAttempts += 1;
        if (user.failedLoginAttempts >= 5) {
          user.status = UserStatus.LOCKED;
        }
        await user.save();
        return null;
      }

      // Reset failed attempts on successful login
      user.failedLoginAttempts = 0;
      user.lastLoginAt = new Date();
      await user.save();

      return user;
    } catch (error) {
      console.error('Password validation error:', error);
      throw new BadRequestException('Password validation failed');
    }
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
        expiresIn: '120m',
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

      if (user.checkLocked()) {
        throw new UnauthorizedException('Account is locked');
      }

      // Update last login time
      user.lastLoginAt = new Date();
      await user.save();

      return this.generateToken(user);
    } catch (error) {
      console.error('Relogin error:', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async changePassword(
    accessToken: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
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
      throw new BadRequestException('Current password is incorrect');
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

    return { message: 'Password changed successfully' };
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
      })
      .exec();

    if (!user) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update user password and clear OTP fields
    user.password = hashedPassword;
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
      console.log('Generated OTP:', otp);
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
      const existingUser = await this.userModel.findOne({ email }).exec();

      if (!existingUser) {
        throw new NotFoundException('User not found');
      }

      // Update user status instead of using isLocked function
      existingUser.status = UserStatus.ACTIVE;

      // Generate random password
      const password = this.generateRandomPassword(8);
      existingUser.password = await bcrypt.hash(password, 10);

      await this.mailService.sendPasswordUserAccount(email, password);
      await existingUser.save();

      const authData = await this.refreshToken(existingUser.refreshToken);
      const newPaymentAccount = await this.accountsService.createOne(
        authData.access_token,
      );

      return !!newPaymentAccount;
    }
    return false;
  }

  private generateRandomPassword(length: number): string {
    const characters =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array(length)
      .fill(null)
      .map(() =>
        characters.charAt(Math.floor(Math.random() * characters.length)),
      )
      .join('');
  }

  async createEmployee(employeeData: any): Promise<UserDocument> {
    const hashedPassword = await bcrypt.hash(employeeData.password, 10);
    const employee = await this.userModel.create({
      ...employeeData,
      password: hashedPassword,
      role: UserRole.EMPLOYEE,
    });
    return employee;
  }

  async findAllEmployees(
    filterDto: EmployeeFilterDto,
  ): Promise<PaginatedResponse<UserDocument>> {
    const {
      page = 1,
      limit = 10,
      search,
      status,
      sortBy,
      sortOrder,
    } = filterDto;
    const skip = (page - 1) * limit;

    // Build filter query
    const filter: any = { role: UserRole.EMPLOYEE };

    if (status) {
      filter.status = status;
    }

    if (search) {
      filter.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { fullName: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
      ];
    }

    // Build sort query
    const sort: any = {};
    if (sortBy) {
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
    } else {
      sort.createdAt = -1; // Default sort
    }

    const [employees, total] = await Promise.all([
      this.userModel
        .find(filter)
        .select(
          '-password -resetPasswordOTP -resetPasswordOTPExpires -refreshToken',
        )
        .skip(skip)
        .limit(limit)
        .sort(sort)
        .exec(),
      this.userModel.countDocuments(filter),
    ]);

    if (!employees.length && page > 1 && total > 0) {
      throw new NotFoundException(`No employees found on page ${page}`);
    }

    return {
      data: employees,
      metadata: {
        total,
        page,
        lastPage: Math.ceil(total / limit),
        limit,
      },
    };
  }

  async findEmployeeById(id: string): Promise<UserDocument> {
    return this.userModel.findOne({ _id: id, role: UserRole.EMPLOYEE }).exec();
  }

  async updateEmployee(id: string, updateData: any): Promise<UserDocument> {
    if (updateData.password) {
      updateData.password = await bcrypt.hash(updateData.password, 10);
    }
    return this.userModel
      .findOneAndUpdate(
        { _id: id, role: UserRole.EMPLOYEE },
        { $set: updateData },
        { new: true },
      )
      .exec();
  }

  async deleteEmployee(id: string): Promise<UserDocument> {
    return this.userModel
      .findOneAndDelete({ _id: id, role: UserRole.EMPLOYEE })
      .exec();
  }

  async lockAccount(accessToken: string): Promise<{ message: string }> {
    const payload = this.jwtService.verify(accessToken);

    const user = await this.userModel.findById(payload.sub).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.status === UserStatus.LOCKED) {
      throw new BadRequestException('Account is already locked');
    }

    user.status = UserStatus.NOTTRANSFER;
    await user.save();

    // Send email notification to user
    await this.mailService.sendAccountLockedEmail(user.email);

    return { message: 'Account locked successfully' };
  }

  async requestUnlock(accessToken: string): Promise<{ message: string }> {
    const payload = this.jwtService.verify(accessToken);

    const user = await this.userModel.findById(payload.sub).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.status !== UserStatus.NOTTRANSFER) {
      throw new BadRequestException('Account is not locked');
    }

    // Generate unlock OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 15); // OTP valid for 15 minutes

    // Save unlock OTP
    user.resetPasswordOTP = otp; // Reusing resetPasswordOTP field for unlock OTP
    user.resetPasswordOTPExpires = otpExpiry;
    await user.save();

    // Send OTP to user's email
    await this.mailService.sendUnlockAccountOtp(user.email, otp);

    return { message: 'Unlock OTP has been sent to your email' };
  }

  async verifyUnlockOtp(
    accessToken: string,
    otp: string,
  ): Promise<{ message: string }> {
    const payload = this.jwtService.verify(accessToken);

    const user = await this.userModel
      .findOne({
        _id: payload.sub,
        resetPasswordOTP: otp,
        resetPasswordOTPExpires: { $gt: new Date() },
      })
      .exec();

    if (!user) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    if (user.status !== UserStatus.NOTTRANSFER) {
      throw new BadRequestException('Account is not locked');
    }

    // Unlock account
    user.status = UserStatus.ACTIVE;
    user.failedLoginAttempts = 0;
    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpires = undefined;
    await user.save();

    // Send confirmation email
    await this.mailService.sendAccountUnlockedEmail(user.email);

    return { message: 'Account unlocked successfully' };
  }
}
