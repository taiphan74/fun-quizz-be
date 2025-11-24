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
import { JwtTokenService } from './services/jwt-token.service';
import { RedisService } from '../../common/redis/redis.service';
import { PrismaService } from '../../common/prisma/prisma.service';
import { AppConfigService } from '../../config/app-config.service';
import type { Response } from 'express';
import { GoogleAuthService } from './services/google-auth.service';
import { OtpService } from './services/otp.service';
import { RefreshTokenStore } from './services/refresh-token.store';

@Injectable()
export class AuthService {
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
    private readonly appConfigService: AppConfigService,
    private readonly googleAuthService: GoogleAuthService,
    private readonly otpService: OtpService,
    private readonly refreshTokenStore: RefreshTokenStore,
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
    const refreshToken = await this.refreshTokenStore.issueForUser(user.id);
    await this.ensureAuthProviderExists(user.id, AuthProviderType.LOCAL);
    return { user: userResponse, accessToken, refreshToken };
  }

  async loginWithGoogleProfile(
    profile: Profile,
  ): Promise<AuthResponseDto & { refreshToken: string }> {
    const user = await this.googleAuthService.loginWithGoogleProfile(profile);
    const userResponse = toUserResponse(user);
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = await this.refreshTokenStore.issueForUser(user.id);
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
    const refreshToken = await this.refreshTokenStore.issueForUser(user.id);
    return { user, accessToken, refreshToken };
  }

  async refreshToken(
    refreshTokenDto: RefreshTokenDto,
  ): Promise<AccessTokenResponseDto> {
    const { refreshToken } = refreshTokenDto;
    const userId = await this.refreshTokenStore.getUserIdByToken(refreshToken);

    if (!userId) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const latestToken = await this.refreshTokenStore.getLatestTokenForUser(
      user.id,
    );

    if (!latestToken || latestToken !== refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const accessToken = this.jwtTokenService.generateAccessToken(user);
    await this.refreshTokenStore.storeForUser(user.id, refreshToken);

    return { accessToken };
  }

  async requestPasswordReset(
    forgotPasswordDto: EmailRequestDto,
  ): Promise<{ message: string }> {
    const email = forgotPasswordDto.email;
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      return { message: 'If the email exists, an OTP has been sent' };
    }

    await this.otpService.sendPasswordResetOtp(
      this.getResetOtpKey(email),
      email,
      this.passwordResetOtpTtlSeconds,
    );

    return { message: 'OTP sent to email' };
  }

  async requestEmailVerificationOtp(
    email: string,
  ): Promise<{ message: string }> {
    const normalizedEmail = email;
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      return { message: 'If the email exists, an OTP has been sent' };
    }

    if (user.emailVerified) {
      return { message: 'Email already verified' };
    }

    await this.otpService.sendEmailVerificationOtp(
      this.getVerifyEmailOtpKey(normalizedEmail),
      normalizedEmail,
      this.passwordResetOtpTtlSeconds,
    );

    return { message: 'Verification OTP sent to email' };
  }

  async verifyEmailOtp(
    verifyEmailOtpDto: VerifyEmailOtpDto,
  ): Promise<{ message: string }> {
    const email = verifyEmailOtpDto.email;
    const otp = verifyEmailOtpDto.otp.trim();
    const storedOtp = await this.otpService.getOtp(
      this.getVerifyEmailOtpKey(email),
    );

    if (!storedOtp || storedOtp !== otp) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    await this.prisma.user.update({
      where: { email },
      data: { emailVerified: true },
    });
    await this.otpService.deleteOtp(this.getVerifyEmailOtpKey(email));

    return { message: 'Email verified successfully' };
  }

  async verifyPasswordResetOtp(verifyResetOtpDto: VerifyResetOtpDto): Promise<{
    message: string;
    resetToken: string;
    expiresInSeconds: number;
  }> {
    const email = verifyResetOtpDto.email;
    const otp = verifyResetOtpDto.otp.trim();
    const storedOtp = await this.otpService.getOtp(this.getResetOtpKey(email));

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
    await this.otpService.deleteOtp(this.getResetOtpKey(email));

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
      if (providerAccountId && !existingProvider.providerAccountId) {
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
