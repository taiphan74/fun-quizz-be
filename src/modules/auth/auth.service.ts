import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { User } from '../users/user.entity';
import { LoginDto, RegisterDto } from './auth.dto';
import { UserResponseDto } from '../users/user.dto';
import { toUserResponse } from '../users/user.mapper';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async login(loginDto: LoginDto): Promise<UserResponseDto> {
    const { usernameOrEmail, password } = loginDto;
    const user = await this.userRepository.findOne({
      where: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
      withDeleted: false,
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.hashPassword);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return toUserResponse(user);
  }

  async register(registerDto: RegisterDto): Promise<UserResponseDto> {
    return this.usersService.create(registerDto);
  }
}
