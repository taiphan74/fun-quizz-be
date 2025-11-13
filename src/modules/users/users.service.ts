import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto, UpdateUserDto, UserResponseDto } from './user.dto';
import { toUserResponse, toUsersResponse } from './user.mapper';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<UserResponseDto> {
    const { password, ...rest } = createUserDto;
    const hash = await bcrypt.hash(password, 10);
    const user = this.userRepository.create({ ...rest, hashPassword: hash });
    const savedUser = await this.userRepository.save(user);
    return toUserResponse(savedUser);
  }

  async findAll(): Promise<UserResponseDto[]> {
    const users = await this.userRepository.find();
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
    const user = await this.findEntityById(id);
    Object.assign(user, updateUserDto);
    const updatedUser = await this.userRepository.save(user);
    return toUserResponse(updatedUser);
  }

  async remove(
    id: string,
  ): Promise<{ message: string; user: UserResponseDto }> {
    const user = await this.findEntityById(id);
    await this.userRepository.remove(user);
    return { message: 'Deleted', user: toUserResponse(user) };
  }

  private async findEntityById(id: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) throw new NotFoundException(`User with id ${id} not found`);
    return user;
  }

  async findByUsernameOrEmail(usernameOrEmail: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
      withDeleted: false,
      select: [
        'id',
        'firstName',
        'lastName',
        'username',
        'email',
        'hashPassword',
        'createdAt',
        'updatedAt',
      ],
    });
  }
}
