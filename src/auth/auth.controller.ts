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

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
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

  @Post('logout')
  @ApiOperation({ summary: 'User logout' })
  @SwaggerResponse({
    status: 200,
    description: 'Logout successful',
  })
  async logout(): Promise<ApiResponse<{ message: string }>> {
    return createSuccessResponse({ message: 'Logged out successfully' });
  }
}
//     },
//   })
//   async logout(): Promise<ApiResponse<{ message: string }>> {
//     return createSuccessResponse({ message: 'Logged out successfully' });
//   }
// }
