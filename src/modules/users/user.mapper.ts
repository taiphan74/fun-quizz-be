import { plainToInstance } from 'class-transformer';
import { User } from './user.entity';
import { UserResponseDto } from './user.dto';

export const toUserResponse = (user: User): UserResponseDto =>
  plainToInstance(UserResponseDto, user, { excludeExtraneousValues: true });

export const toUsersResponse = (users: User[]): UserResponseDto[] =>
  users.map((user) => toUserResponse(user));
