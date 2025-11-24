import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import type { Profile } from 'passport-google-oauth20';
import { AuthProviderType } from '@prisma/client';
import { UsersService } from '../users/users.service';
import { UserRole } from '../users/user-role.enum';
import {
  AccessTokenResponseDto,
  AuthResponseDto,
  LoginDto,
  RefreshTokenDto,
  RegisterDto,
  EmailRequestDto,
  VerifyResetOtpDto,
  ResetPasswordDto,
  VerifyEmailOtpDto,
} from './auth.dto';
import { toUserResponse } from '../users/user.mapper';
import { JwtTokenService } from './jwt-token.service';
import { RedisService } from '../../common/redis/redis.service';
import { JwtPayload } from './types/jwt-payload.interface';
import { PrismaService } from '../../common/prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import { AppConfigService } from '../../config/app-config.service';
import { generateNumericOtp } from '../../common/algorithms/otp.util';
import type { Response } from 'express';
import { GoogleAuthService } from './google-auth.service';

@Injectable()
export class AuthService {
  private readonly refreshTokenKeyPrefix = 'refresh-token';
  private readonly resetOtpKeyPrefix = 'password-reset-otp';
  private readonly resetTokenKeyPrefix = 'password-reset-token';
  private readonly resetTokenTtlSeconds = 5 * 60; // 5 minutes
  private readonly verifyEmailOtpKeyPrefix = 'verify-email-otp';
  private readonly passwordResetOtpTtlSeconds: number;
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtTokenService: JwtTokenService,
    private readonly redisService: RedisService,
    private readonly prisma: PrismaService,
    private readonly mailService: MailService,
    private readonly appConfigService: AppConfigService,
    private readonly googleAuthService: GoogleAuthService,
  ) {
    this.passwordResetOtpTtlSeconds =
      this.appConfigService.getPasswordResetConfig().otpTtlSeconds;
  }

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
    await this.ensureAuthProviderExists(user.id, AuthProviderType.LOCAL);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user: userResponse, accessToken, refreshToken };
  }

  async loginWithGoogleProfile(
    profile: Profile,
  ): Promise<AuthResponseDto & { refreshToken: string }> {
    const user = await this.googleAuthService.loginWithGoogleProfile(profile);
    const userResponse = toUserResponse(user);
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = this.jwtTokenService.generateRefreshToken(user);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user: userResponse, accessToken, refreshToken };
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
    forgotPasswordDto: EmailRequestDto,
  ): Promise<{ message: string }> {
    const email = forgotPasswordDto.email.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      return { message: 'If the email exists, an OTP has been sent' };
    }

    const otp = generateNumericOtp();
    await this.redisService.set(
      this.getResetOtpKey(email),
      otp,
      this.passwordResetOtpTtlSeconds,
    );
    await this.mailService.sendOtpEmail(email, otp);

    return { message: 'OTP sent to email' };
  }

  async requestEmailVerificationOtp(
    email: string,
  ): Promise<{ message: string }> {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      return { message: 'If the email exists, an OTP has been sent' };
    }

    if (user.emailVerified) {
      return { message: 'Email already verified' };
    }

    const otp = generateNumericOtp();
    await this.redisService.set(
      this.getVerifyEmailOtpKey(normalizedEmail),
      otp,
      this.passwordResetOtpTtlSeconds,
    );
    await this.mailService.sendEmailVerificationOtp(normalizedEmail, otp);

    return { message: 'Verification OTP sent to email' };
  }

  async verifyEmailOtp(
    verifyEmailOtpDto: VerifyEmailOtpDto,
  ): Promise<{ message: string }> {
    const email = verifyEmailOtpDto.email.trim().toLowerCase();
    const otp = verifyEmailOtpDto.otp.trim();
    const storedOtp = await this.redisService.get(
      this.getVerifyEmailOtpKey(email),
    );

    if (!storedOtp || storedOtp !== otp) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    await this.prisma.user.update({
      where: { email },
      data: { emailVerified: true },
    });
    await this.redisService.delete(this.getVerifyEmailOtpKey(email));

    return { message: 'Email verified successfully' };
  }

  async verifyPasswordResetOtp(
    verifyResetOtpDto: VerifyResetOtpDto,
  ): Promise<{ message: string; resetToken: string; expiresInSeconds: number }> {
    const email = verifyResetOtpDto.email.trim().toLowerCase();
    const otp = verifyResetOtpDto.otp.trim();
    const storedOtp = await this.redisService.get(this.getResetOtpKey(email));

    if (!storedOtp || storedOtp !== otp) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    const resetToken = randomBytes(32).toString('hex');
    await this.redisService.set(
      this.getResetTokenKey(resetToken),
      email,
      this.resetTokenTtlSeconds,
    );
    // Delete OTP after successful verification to prevent reuse
    await this.redisService.delete(this.getResetOtpKey(email));

    return {
      message: 'OTP verified. Use reset token to update password',
      resetToken,
      expiresInSeconds: this.resetTokenTtlSeconds,
    };
  }

  async resetPassword(
    resetPasswordDto: ResetPasswordDto & { resetToken?: string },
  ): Promise<{ message: string }> {
    const { resetToken, newPassword } = resetPasswordDto;
    const token = resetToken ?? '';
    if (!token) {
      throw new UnauthorizedException('Reset token is missing');
    }

    const email = await this.redisService.get<string>(
      this.getResetTokenKey(token),
    );

    if (!email) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invalid reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { hashPassword: hashedPassword },
    });

    // Cleanup token to prevent reuse
    await this.redisService.delete(this.getResetTokenKey(token));

    return { message: 'Password has been reset' };
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

  private getResetTokenKey(token: string): string {
    return `${this.resetTokenKeyPrefix}:${token}`;
  }

  private getVerifyEmailOtpKey(email: string): string {
    return `${this.verifyEmailOtpKeyPrefix}:${email}`;
  }

  setRefreshTokenCookie(res: Response, refreshToken: string): void {
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: this.appConfigService.nodeEnv === 'production',
      sameSite: 'lax',
      path: '/',
    });
  }

  setResetTokenCookie(
    res: Response,
    resetToken: string,
    ttlSeconds: number,
  ): void {
    res.cookie('resetToken', resetToken, {
      httpOnly: true,
      secure: this.appConfigService.nodeEnv === 'production',
      sameSite: 'lax',
      path: '/auth/reset-password',
      maxAge: ttlSeconds * 1000,
    });
  }

  private generateRandomPassword(): string {
    return randomBytes(24).toString('hex');
  }

  private async ensureAuthProviderExists(
    userId: string,
    provider: AuthProviderType,
    providerAccountId?: string | null,
  ): Promise<void> {
    const existingProvider = await this.prisma.authProvider.findFirst({
      where: { userId, provider },
    });

    if (existingProvider) {
      if (
        providerAccountId &&
        !existingProvider.providerAccountId
      ) {
        await this.prisma.authProvider.update({
          where: { id: existingProvider.id },
          data: { providerAccountId },
        });
      }
      return;
    }

    await this.prisma.authProvider.create({
      data: {
        userId,
        provider,
        providerAccountId: providerAccountId ?? undefined,
      },
    });
  }
}
