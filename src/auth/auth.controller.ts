import { Controller, Post, Body, HttpStatus } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse as SwaggerResponse,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto/auth.dto';
import {
  ApiResponse,
  createSuccessResponse,
  createErrorResponse,
} from '../ApiRespose/interface/response.interface';
import { AuthData } from './interfaces/auth.interface';
import { BearerToken } from './decorators/auth.decorator';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOperation({ summary: 'User login' })
  @SwaggerResponse({
    status: 200,
    description: 'Login successful',
  })
  async login(@Body() loginDto: LoginDto): Promise<ApiResponse<AuthData>> {
    try {
      const result = await this.authService.login(
        loginDto.username,
        loginDto.password,
      );
      return createSuccessResponse(result);
    } catch (error) {
      return createErrorResponse(
        error.status || HttpStatus.UNAUTHORIZED,
        error.message || 'Authentication failed',
      );
    }
  }

  @Post('register')
  @ApiOperation({ summary: 'User registration' })
  @SwaggerResponse({
    status: 201,
    description: 'Registration successful',
  })
  async register(
    @Body() registerDto: RegisterDto,
  ): Promise<ApiResponse<AuthData>> {
    try {
      const result = await this.authService.register(registerDto);
      return createSuccessResponse(result);
    } catch (error) {
      return createErrorResponse(
        error.status || HttpStatus.BAD_REQUEST,
        error.message || 'Registration failed',
      );
    }
  }

  @Post('refresh-token')
  @ApiOperation({ summary: 'Refresh access token' })
  @SwaggerResponse({
    status: 200,
    description: 'Token refresh successful',
  })
  async refreshToken(
    @BearerToken() refreshToken: string,
  ): Promise<ApiResponse<AuthData>> {
    try {
      const result = await this.authService.refreshToken(refreshToken);
      return createSuccessResponse(result);
    } catch (error) {
      return createErrorResponse(
        error.status || HttpStatus.UNAUTHORIZED,
        error.message || 'Token refresh failed',
      );
    }
  }

  @Post('logout')
  @ApiOperation({ summary: 'User logout' })
  @SwaggerResponse({
    status: 200,
    description: 'Logout successful',
  })
  async logout(): Promise<ApiResponse<{ message: string }>> {
    return createSuccessResponse({ message: 'Logged out successfully' });
  }

  @Post('verify-token')
  @ApiOperation({ summary: 'Verify access token' })
  @SwaggerResponse({
    status: 200,
    description: 'Token verification result',
  })
  async verifyToken(
    @BearerToken() accessToken: string,
  ): Promise<
    ApiResponse<{ isValid: boolean; isExpired: boolean; message?: string }>
  > {
    try {
      console.log('accessToken', accessToken);
      const result = await this.authService.verifyAccessToken(accessToken);
      return createSuccessResponse(result);
    } catch (error) {
      return createErrorResponse(
        error.status || HttpStatus.UNAUTHORIZED,
        error.message || 'Token verification failed',
      );
    }
  }

  @Post('relogin')
  @ApiOperation({ summary: 'Re-login with access token' })
  @SwaggerResponse({
    status: 200,
    description: 'Re-login successful',
  })
  async reLogin(
    @BearerToken() accessToken: string,
  ): Promise<ApiResponse<AuthData>> {
    try {
      const result = await this.authService.reLoginWithToken(accessToken);
      return createSuccessResponse(result);
    } catch (error) {
      return createErrorResponse(
        error.status || HttpStatus.UNAUTHORIZED,
        error.message || 'Re-login failed with token',
      );
    }
  }
}
