import { ApiProperty, PartialType, OmitType } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength, IsOptional } from 'class-validator';
import { User } from './user.entity';

export class CreateUserDto extends OmitType(User, [
  'id',
  'hashPassword',
  'resetPasswordToken',
  'resetPasswordExpiresAt',
  'createdAt',
  'updatedAt',
  'deletedAt',
] as const) {
  @ApiProperty({ example: 'secret123', minLength: 6 })
  @IsNotEmpty()
  @MinLength(6)
  password: string;
}

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsOptional()
  @MinLength(6)
  password?: string;
}

export class UserResponseDto extends OmitType(User, [
  'hashPassword',
  'resetPasswordToken',
  'resetPasswordExpiresAt',
  'deletedAt',
] as const) {}
