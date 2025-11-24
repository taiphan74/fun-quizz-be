import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiCreatedResponse, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import {
  AccessTokenResponseDto,
  AuthResponseDto,
  LoginDto,
  RegisterDto,
  EmailRequestDto,
  VerifyResetOtpDto,
  ResetPasswordDto,
  VerifyEmailOtpDto,
} from './auth.dto';
import { GoogleOAuthGuard } from './guards/google-auth.guard';
import type { Request, Response } from 'express';
import type { Profile } from 'passport-google-oauth20';
import { AppConfigService } from '../../config/app-config.service';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly appConfigService: AppConfigService,
  ) {}

  @Post('login')
  @ApiOkResponse({
    description: 'User successfully authenticated',
    type: AuthResponseDto,
  })
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const { refreshToken, ...response } =
      await this.authService.login(loginDto);
    this.authService.setRefreshTokenCookie(res, refreshToken);
    return response;
  }

  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  googleAuth(): void {
    return;
  }

  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  @ApiOkResponse({
    description:
      'Redirects to frontend with access token appended as a query param',
  })
  async googleAuthCallback(
    @Req() req: Request & { user?: Profile },
    @Res() res: Response,
  ): Promise<void> {
    const profile = req.user;
    if (!profile) {
      throw new UnauthorizedException('Google authentication failed');
    }
    const { refreshToken } =
      await this.authService.loginWithGoogleProfile(profile);
    this.authService.setRefreshTokenCookie(res, refreshToken);
    const { frontendRedirectUrl } =
      this.appConfigService.getGoogleOAuthConfig();
    res.redirect(frontendRedirectUrl);
  }

  @Post('register')
  @ApiCreatedResponse({
    description: 'User successfully registered',
    type: AuthResponseDto,
  })
  async register(
    @Body() registerDto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponseDto> {
    const { refreshToken, ...response } =
      await this.authService.register(registerDto);
    this.authService.setRefreshTokenCookie(res, refreshToken);
    return response;
  }

  @Post('refresh')
  @ApiOkResponse({
    description: 'Access token successfully refreshed',
    type: AccessTokenResponseDto,
  })
  refresh(@Req() req: Request): Promise<AccessTokenResponseDto> {
    const cookies = (req as unknown as { cookies?: Record<string, string> })
      .cookies;
    const refreshToken = cookies?.refreshToken;
    // Debug: log refresh token from cookies

    console.log('Refresh token from cookies:', refreshToken);
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }
    return this.authService.refreshToken({ refreshToken });
  }

  @Post('forgot-password')
  @ApiOkResponse({ description: 'Sends OTP to email if account exists' })
  forgotPassword(
    @Body() forgotPasswordDto: EmailRequestDto,
  ): Promise<{ message: string }> {
    return this.authService.requestPasswordReset(forgotPasswordDto);
  }

  @Post('verify-reset-otp')
  @ApiOkResponse({ description: 'Verifies password reset OTP' })
  verifyResetOtp(
    @Body() verifyResetOtpDto: VerifyResetOtpDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string; expiresInSeconds: number }> {
    return this.authService
      .verifyPasswordResetOtp(verifyResetOtpDto)
      .then(({ message, resetToken, expiresInSeconds }) => {
        this.authService.setResetTokenCookie(res, resetToken, expiresInSeconds);
        return { message, expiresInSeconds };
      });
  }

  @Post('reset-password')
  @ApiOkResponse({ description: 'Resets password using reset token' })
  resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() req: Request,
  ): Promise<{ message: string }> {
    const cookies = (req as unknown as { cookies?: Record<string, string> })
      .cookies;
    const resetToken = cookies?.resetToken || '';
    return this.authService.resetPassword({
      ...resetPasswordDto,
      resetToken,
    });
  }

  @Post('request-email-verification')
  @ApiOkResponse({ description: 'Sends OTP for email verification if needed' })
  requestEmailVerification(
    @Body() forgotPasswordDto: EmailRequestDto,
  ): Promise<{ message: string }> {
    return this.authService.requestEmailVerificationOtp(
      forgotPasswordDto.email,
    );
  }

  @Post('verify-email-otp')
  @ApiOkResponse({ description: 'Verify email using OTP' })
  verifyEmailOtp(
    @Body() verifyEmailOtpDto: VerifyEmailOtpDto,
  ): Promise<{ message: string }> {
    return this.authService.verifyEmailOtp(verifyEmailOtpDto);
  }
}
