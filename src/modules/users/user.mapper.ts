import { plainToInstance } from 'class-transformer';
import type { User } from '@prisma/client';
import { UserResponseDto } from './user.dto';

export const toUserResponse = (user: User): UserResponseDto =>
  plainToInstance(UserResponseDto, user, { excludeExtraneousValues: true });

export const toUsersResponse = (users: User[]): UserResponseDto[] =>
  users.map((user) => toUserResponse(user));
