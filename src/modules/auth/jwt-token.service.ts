import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './types/jwt-payload.interface';
import type { User } from '@prisma/client';
import { UserResponseDto } from '../users/user.dto';
import { AppConfigService } from '../../config/app-config.service';

type JwtSource =
  | Pick<User, 'id' | 'username' | 'email' | 'role'>
  | Pick<UserResponseDto, 'id' | 'username' | 'email' | 'role'>;

@Injectable()
export class JwtTokenService {
  private readonly refreshTokenSecret: string;
  private readonly refreshTokenExpiresInSeconds: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: AppConfigService,
  ) {
    const refreshConfig = this.configService.getJwtRefreshConfig();
    this.refreshTokenSecret = refreshConfig.secret;
    this.refreshTokenExpiresInSeconds = refreshConfig.expiresInSeconds;
  }

  generateAccessToken(user: JwtSource): string {
    const payload = this.buildPayload(user);
    return this.jwtService.sign(payload);
  }

  generateRefreshToken(user: JwtSource): string {
    const payload = this.buildPayload(user);
    return this.jwtService.sign(payload, {
      secret: this.refreshTokenSecret,
      expiresIn: this.refreshTokenExpiresInSeconds,
    });
  }

  verifyRefreshToken(token: string): JwtPayload {
    return this.jwtService.verify<JwtPayload>(token, {
      secret: this.refreshTokenSecret,
    });
  }

  getRefreshTokenTtlSeconds(): number {
    return this.refreshTokenExpiresInSeconds;
  }

  private buildPayload(user: JwtSource): JwtPayload {
    return {
      sub: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };
  }
}
