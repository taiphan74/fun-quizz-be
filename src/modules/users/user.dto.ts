import { ApiProperty, OmitType, PartialType } from '@nestjs/swagger';
import { Exclude, Expose } from 'class-transformer';
import { IsNotEmpty, IsOptional, MinLength } from 'class-validator';
import { User } from './user.entity';

export class CreateUserDto extends OmitType(User, [
  'id',
  'hashPassword',
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

@Exclude()
export class UserResponseDto {
  @Expose()
  id: string;

  @Expose()
  firstName: string;

  @Expose()
  lastName: string;

  @Expose()
  username: string;

  @Expose()
  email: string;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}
