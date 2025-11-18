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
  login(@Body() loginDto: LoginDto): Promise<AuthResponseDto> {
    return this.authService.login(loginDto);
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
    const authResponse = await this.authService.loginWithGoogleProfile(profile);
    res.cookie('refreshToken', authResponse.refreshToken, {
      httpOnly: true,
      secure: this.appConfigService.nodeEnv === 'production',
      sameSite: 'lax',
      path: '/',
    });
    const { frontendRedirectUrl } =
      this.appConfigService.getGoogleOAuthConfig();
    res.redirect(frontendRedirectUrl);
  }

  @Post('register')
  @ApiCreatedResponse({
    description: 'User successfully registered',
    type: AuthResponseDto,
  })
  register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
    return this.authService.register(registerDto);
  }

  @Post('refresh')
  @ApiOkResponse({
    description: 'Access token successfully refreshed',
    type: AccessTokenResponseDto,
  })
  refresh(
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<AccessTokenResponseDto> {
    return this.authService.refreshToken(refreshTokenDto);
  }
}
