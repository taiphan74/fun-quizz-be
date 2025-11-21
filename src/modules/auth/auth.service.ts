import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import type { Profile } from 'passport-google-oauth20';
import type { User } from '@prisma/client';
import { UsersService } from '../users/users.service';
import { UserRole } from '../users/user-role.enum';
import {
  AccessTokenResponseDto,
  AuthResponseDto,
  LoginDto,
  RefreshTokenDto,
  RegisterDto,
  ForgotPasswordDto,
} from './auth.dto';
import { toUserResponse } from '../users/user.mapper';
import { JwtTokenService } from './jwt-token.service';
import { RedisService } from '../../common/redis/redis.service';
import { JwtPayload } from './types/jwt-payload.interface';
import { PrismaService } from '../../common/prisma/prisma.service';
import { MailService } from '../mail/mail.service';

interface GoogleAccountPayload {
  email?: string | null;
  givenName?: string | null;
  familyName?: string | null;
}

@Injectable()
export class AuthService {
  private readonly refreshTokenKeyPrefix = 'refresh-token';
  private readonly resetOtpKeyPrefix = 'password-reset-otp';
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtTokenService: JwtTokenService,
    private readonly redisService: RedisService,
    private readonly prisma: PrismaService,
    private readonly mailService: MailService,
  ) {}

  async login(
    loginDto: LoginDto,
  ): Promise<AuthResponseDto & { refreshToken: string }> {
    const { usernameOrEmail, password } = loginDto;
    const user = await this.usersService.findByUsernameOrEmail(usernameOrEmail);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.hashPassword);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const userResponse = toUserResponse(user);
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = this.jwtTokenService.generateRefreshToken(user);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user: userResponse, accessToken, refreshToken };
  }

  async loginWithGoogleProfile(
    profile: Profile,
  ): Promise<AuthResponseDto & { refreshToken: string }> {
    return this.authenticateGoogleAccount({
      email: profile.emails?.[0]?.value,
      givenName: profile.name?.givenName,
      familyName: profile.name?.familyName,
    });
  }

  async register(
    registerDto: RegisterDto,
  ): Promise<AuthResponseDto & { refreshToken: string }> {
    const user = await this.usersService.create({
      ...registerDto,
      role: UserRole.USER,
    });
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = this.jwtTokenService.generateRefreshToken(user);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user, accessToken, refreshToken };
  }

  async refreshToken(
    refreshTokenDto: RefreshTokenDto,
  ): Promise<AccessTokenResponseDto> {
    const { refreshToken } = refreshTokenDto;
    const payload = this.verifyRefreshToken(refreshToken);
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const storedRefreshToken = await this.redisService.get(
      this.getRefreshTokenKey(user.id),
    );

    if (!storedRefreshToken || storedRefreshToken !== refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const accessToken = this.jwtTokenService.generateAccessToken(user);
    await this.storeRefreshToken(user.id, refreshToken);

    return { accessToken };
  }

  async requestPasswordReset(
    forgotPasswordDto: ForgotPasswordDto,
  ): Promise<{ message: string }> {
    const email = forgotPasswordDto.email.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      return { message: 'If the email exists, an OTP has been sent' };
    }

    const otp = this.generateOtp();
    const ttlSeconds = 10 * 60; // 10 minutes
    await this.redisService.set(this.getResetOtpKey(email), otp, ttlSeconds);
    await this.mailService.sendOtpEmail(email, otp);

    return { message: 'OTP sent to email' };
  }

  private async authenticateGoogleAccount(
    payload: GoogleAccountPayload,
  ): Promise<AuthResponseDto & { refreshToken: string }> {
    const user = await this.findOrCreateGoogleUser(payload);
    const userResponse = toUserResponse(user);
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = this.jwtTokenService.generateRefreshToken(user);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user: userResponse, accessToken, refreshToken };
  }

  private getRefreshTokenKey(userId: string): string {
    return `${this.refreshTokenKeyPrefix}:${userId}`;
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const ttl = this.jwtTokenService.getRefreshTokenTtlSeconds();
    await this.redisService.set(
      this.getRefreshTokenKey(userId),
      refreshToken,
      ttl,
    );
  }

  private verifyRefreshToken(refreshToken: string): JwtPayload {
    try {
      return this.jwtTokenService.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private getResetOtpKey(email: string): string {
    return `${this.resetOtpKeyPrefix}:${email}`;
  }

  private generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  private async findOrCreateGoogleUser(
    payload: GoogleAccountPayload,
  ): Promise<User> {
    const email = payload.email;

    if (!email) {
      throw new UnauthorizedException('Google account is missing an email');
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return existingUser;
    }

    const username = await this.generateUniqueUsername(email);
    const hashPassword = await bcrypt.hash(this.generateRandomPassword(), 10);

    return this.prisma.user.create({
      data: {
        email,
        username,
        firstName: payload.givenName ?? '',
        lastName: payload.familyName ?? '',
        role: UserRole.USER,
        hashPassword,
      },
    });
  }

  private async generateUniqueUsername(email: string): Promise<string> {
    const prefix = email.split('@')[0]?.replace(/[^a-zA-Z0-9]/g, '') || 'user';
    const base = prefix.length > 0 ? prefix.toLowerCase() : 'user';
    let candidate = base;
    let attempt = 0;

    while (
      await this.prisma.user.findUnique({
        where: { username: candidate },
      })
    ) {
      attempt += 1;
      candidate = `${base}${attempt}`;
    }

    return candidate;
  }

  private generateRandomPassword(): string {
    return randomBytes(24).toString('hex');
  }
}
