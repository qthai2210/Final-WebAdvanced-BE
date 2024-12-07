import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsEmail,
  IsEnum,
  IsOptional,
  MinLength,
  IsDateString,
} from 'class-validator';
import { UserRole } from '../schemas/user.schema';

export class LoginDto {
  @ApiProperty({ example: 'johndoe', description: 'Username for login' })
  @IsString()
  username: string;

  @ApiProperty({ example: 'password123', description: 'User password' })
  @IsString()
  @MinLength(6)
  password: string;
}

export class RegisterDto {
  @ApiProperty({ example: 'johndoe', description: 'Unique username' })
  @IsString()
  username: string;

  @ApiProperty({
    example: 'password123',
    description: 'Password minimum 6 characters',
  })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({
    example: 'john@example.com',
    description: 'Valid email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '+1234567890', description: 'Phone number' })
  @IsString()
  phone: string;

  @ApiProperty({ example: 'John Doe', description: 'Full name of the user' })
  @IsString()
  fullName: string;

  @ApiPropertyOptional({ example: 'ID123456', description: 'Identity number' })
  @IsOptional()
  @IsString()
  identityNumber?: string;

  @ApiPropertyOptional({ example: '1990-01-01', description: 'Date of birth' })
  @IsOptional()
  @IsDateString()
  dateOfBirth?: Date;

  @ApiPropertyOptional({ example: '123 Main St', description: 'User address' })
  @IsOptional()
  @IsString()
  address?: string;

  @ApiPropertyOptional({ enum: UserRole, default: UserRole.CUSTOMER })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
