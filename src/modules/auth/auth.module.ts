import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtTokenService } from './services/jwt-token.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { AppConfigService } from '../../config/app-config.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { GoogleOAuthGuard } from './guards/google-auth.guard';
import { GoogleAuthService } from './google-auth.service';
import { OtpModule } from '../otp/otp.module';
import { RefreshTokenStore } from './services/refresh-token.store';

@Module({
  imports: [
    UsersModule,
    OtpModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      inject: [AppConfigService],
      useFactory: (config: AppConfigService) => {
        const jwtConfig = config.getJwtConfig();
        return {
          secret: jwtConfig.secret,
          signOptions: {
            expiresIn: jwtConfig.expiresInSeconds,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtTokenService,
    JwtStrategy,
    JwtAuthGuard,
    RolesGuard,
    GoogleStrategy,
    GoogleOAuthGuard,
    GoogleAuthService,
    RefreshTokenStore,
  ],
  exports: [
    AuthService,
    JwtTokenService,
    JwtAuthGuard,
    RolesGuard,
    GoogleOAuthGuard,
  ],
})
export class AuthModule {}
