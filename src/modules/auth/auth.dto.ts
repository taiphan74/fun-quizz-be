import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, MinLength } from 'class-validator';
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

export class RegisterDto extends CreateUserDto {}

export class AuthResponseDto {
  @ApiProperty({ type: UserResponseDto })
  user: UserResponseDto;

  @ApiProperty({
    description: 'JWT access token that must be sent as a Bearer token',
  })
  accessToken: string;

  @ApiProperty({
    description: 'JWT refresh token used to request new access tokens',
  })
  refreshToken: string;
}
