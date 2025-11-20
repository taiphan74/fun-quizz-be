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
  RefreshTokenDto,
  RegisterDto,
} from './auth.dto';
import { GoogleOAuthGuard } from './guards/google-auth.guard';
import type { Request } from 'express';
import type { Profile } from 'passport-google-oauth20';
import type { Response } from 'express';
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
    const { refreshToken, ...response } = await this.authService.login(
      loginDto,
    );
    this.setRefreshTokenCookie(res, refreshToken);
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
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const profile = req.user as Profile | undefined;
    if (!profile) {
      throw new UnauthorizedException('Google authentication failed');
    }
    const { refreshToken } =
      await this.authService.loginWithGoogleProfile(profile);
    this.setRefreshTokenCookie(res, refreshToken);
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
    const { refreshToken, ...response } = await this.authService.register(
      registerDto,
    );
    this.setRefreshTokenCookie(res, refreshToken);
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
    // eslint-disable-next-line no-console
    console.log('Refresh token from cookies:', refreshToken);
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }
    return this.authService.refreshToken({ refreshToken });
  }

  private setRefreshTokenCookie(res: Response, refreshToken: string): void {
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: this.appConfigService.nodeEnv === 'production',
      sameSite: 'lax',
      path: '/',
    });
  }
}
