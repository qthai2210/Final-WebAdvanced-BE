import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User, UserDocument, UserStatus } from './schemas/user.schema';
import { RegisterDto } from './dto/auth.dto';

import { AuthData } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthData> {
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
    const newUser = new this.userModel({
      ...registerDto,
      password: hashedPassword,
      status: UserStatus.PENDING,
      failedLoginAttempts: 0,
    });

    const savedUser = await newUser.save();
    return this.generateToken(savedUser);
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

  async verifyAccessToken(accessToken: string): Promise<boolean> {
    try {
      const payload = this.jwtService.verify(accessToken);
      if (payload.type !== 'access_token') {
        return false;
      }

      const user = await this.userModel.findById(payload.sub).exec();
      if (!user) {
        return false;
      }

      return true;
    } catch (error) {
      return false;
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
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
