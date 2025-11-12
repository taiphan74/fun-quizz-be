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
