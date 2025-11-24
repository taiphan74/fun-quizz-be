import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  IsOptional,
  MinLength,
} from 'class-validator';
import { CreateUserDto, UserResponseDto } from '../users/user.dto';

export class LoginDto {
  @ApiProperty({
    description: 'Username or email used during registration',
    example: 'johndoe',
  })
  @IsNotEmpty()
  usernameOrEmail: string;

  @ApiProperty({ example: 'secret123', minLength: 6 })
  @IsNotEmpty()
  @MinLength(6)
  password: string;
}

export class RegisterDto
  implements Pick<CreateUserDto, 'username' | 'email' | 'password'>
{
  @ApiProperty({ example: 'johndoe', description: 'Unique username' })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({ example: 'john@example.com', description: 'User email' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'secret123', minLength: 6 })
  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  password: string;
}

export class RefreshTokenDto {
  @ApiProperty({
    description: 'JWT refresh token used to request new access tokens',
  })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}

export class AuthResponseDto {
  @ApiProperty({ type: UserResponseDto })
  user: UserResponseDto;

  @ApiProperty({
    description: 'JWT access token that must be sent as a Bearer token',
  })
  accessToken: string;
}

export class AccessTokenResponseDto {
  @ApiProperty({
    description: 'JWT access token that must be sent as a Bearer token',
  })
  accessToken: string;
}

export class EmailRequestDto {
  @ApiProperty({
    description: 'Email associated with the account',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}

export class VerifyResetOtpDto {
  @ApiProperty({
    description: 'Email associated with the OTP',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ description: 'OTP received via email', example: '123456' })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;
}

export class ResetPasswordDto {
  @ApiProperty({ description: 'New password', example: 'newsecret123' })
  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  newPassword: string;
}

export class VerifyEmailOtpDto {
  @ApiProperty({
    description: 'Email to verify',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ description: 'OTP sent to the email', example: '123456' })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;
}
