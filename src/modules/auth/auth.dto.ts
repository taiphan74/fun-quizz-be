import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, MinLength } from 'class-validator';
import { CreateUserDto } from '../users/user.dto';

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

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Username or email of the account to reset',
    example: 'johndoe',
  })
  @IsNotEmpty()
  usernameOrEmail: string;
}

export class ResetPasswordDto {
  @ApiProperty({
    description: 'Reset token previously issued using forgot password flow',
    example: 'b9e8f5a2008446eaa825b7a7f79269fa',
  })
  @IsNotEmpty()
  token: string;

  @ApiProperty({ example: 'newSecret123', minLength: 6 })
  @IsNotEmpty()
  @MinLength(6)
  newPassword: string;
}
