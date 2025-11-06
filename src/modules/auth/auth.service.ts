import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { User } from '../users/user.entity';
import { ForgotPasswordDto, LoginDto, RegisterDto, ResetPasswordDto } from './auth.dto';
import { UserResponseDto } from '../users/user.dto';
import { randomBytes } from 'crypto';

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
      where: [
        { username: usernameOrEmail },
        { email: usernameOrEmail },
      ],
      withDeleted: false,
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.hashPassword);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.toResponse(user);
  }

  async register(registerDto: RegisterDto): Promise<UserResponseDto> {
    return this.usersService.create(registerDto);
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
  ): Promise<{ message: string; resetToken?: string }> {
    const { usernameOrEmail } = forgotPasswordDto;
    const user = await this.userRepository.findOne({
      where: [
        { username: usernameOrEmail },
        { email: usernameOrEmail },
      ],
      withDeleted: false,
    });

    if (!user) {
      return { message: 'If the account exists, a reset token has been generated.' };
    }

    const resetToken = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = expiresAt;
    await this.userRepository.save(user);

    return {
      message: 'Reset token generated. Please check your email.',
      resetToken,
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<UserResponseDto> {
    const { token, newPassword } = resetPasswordDto;

    const user = await this.userRepository.findOne({
      where: { resetPasswordToken: token },
      withDeleted: false,
    });

    if (
      !user ||
      !user.resetPasswordExpiresAt ||
      user.resetPasswordExpiresAt.getTime() < Date.now()
    ) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const hash = await bcrypt.hash(newPassword, 10);
    user.hashPassword = hash;
    user.resetPasswordToken = null;
    user.resetPasswordExpiresAt = null;

    const savedUser = await this.userRepository.save(user);
    return this.toResponse(savedUser);
  }

  private toResponse(user: User): UserResponseDto {
    const {
      hashPassword,
      deletedAt,
      resetPasswordToken,
      resetPasswordExpiresAt,
      ...response
    } = user;
    return response as UserResponseDto;
  }
}
