import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './types/jwt-payload.interface';
import { User } from '../users/user.entity';
import { UserResponseDto } from '../users/user.dto';

type JwtSource =
  | Pick<User, 'id' | 'username' | 'email' | 'role'>
  | Pick<UserResponseDto, 'id' | 'username' | 'email' | 'role'>;

@Injectable()
export class JwtTokenService {
  private readonly refreshTokenSecret: string;
  private readonly defaultRefreshTtlSeconds = 60 * 60 * 24 * 7; // 7 days
  private readonly refreshTokenExpiresInSeconds: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.refreshTokenSecret = this.configService.get<string>(
      'JWT_REFRESH_SECRET',
      this.configService.get<string>('JWT_SECRET', 'changeme'),
    );
    const refreshExpiresInConfig =
      this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') ??
      String(this.defaultRefreshTtlSeconds);
    const parsedTtl = parseInt(refreshExpiresInConfig, 10);
    this.refreshTokenExpiresInSeconds = Number.isNaN(parsedTtl)
      ? this.defaultRefreshTtlSeconds
      : parsedTtl;
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
