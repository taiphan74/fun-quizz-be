import { Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto, UpdateUserDto, UserResponseDto } from './user.dto';
import { toUserResponse, toUsersResponse } from './user.mapper';
import { PrismaService } from '../../common/prisma/prisma.service';
import { UserRole } from './user-role.enum';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto): Promise<UserResponseDto> {
    const { password, role, ...rest } = createUserDto;
    const hash = await bcrypt.hash(password, 10);
    const userRole = role ?? UserRole.USER;
    const savedUser = await this.prisma.user.create({
      data: {
        ...rest,
        role: userRole,
        hashPassword: hash,
      },
    });
    return toUserResponse(savedUser);
  }

  async findAll(): Promise<UserResponseDto[]> {
    const users = await this.prisma.user.findMany();
    return toUsersResponse(users);
  }

  async findOne(id: string): Promise<UserResponseDto> {
    const user = await this.findEntityById(id);
    return toUserResponse(user);
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
  ): Promise<UserResponseDto> {
    await this.findEntityById(id);
    const { password, ...rest } = updateUserDto;
    const data: Prisma.UserUpdateInput = { ...rest };

    if (password) {
      data.hashPassword = await bcrypt.hash(password, 10);
    }

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data,
    });
    return toUserResponse(updatedUser);
  }

  async remove(
    id: string,
  ): Promise<{ message: string; user: UserResponseDto }> {
    await this.findEntityById(id);
    const deletedUser = await this.prisma.user.delete({ where: { id } });
    return { message: 'Deleted', user: toUserResponse(deletedUser) };
  }

  private async findEntityById(id: string): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
    return user;
  }

  async findByUsernameOrEmail(usernameOrEmail: string): Promise<User | null> {
    return this.prisma.user.findFirst({
      where: {
        OR: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
      },
    });
  }
}
