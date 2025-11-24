import { Injectable } from '@nestjs/common';
import { RedisService } from '../../../common/redis/redis.service';
import { JwtTokenService } from './jwt-token.service';
import { randomBytes } from 'crypto';

@Injectable()
export class RefreshTokenStore {
  private readonly refreshTokenKeyPrefix = 'refresh-token';

  constructor(
    private readonly redisService: RedisService,
    private readonly jwtTokenService: JwtTokenService,
  ) {}

  generateToken(): string {
    return randomBytes(64).toString('hex');
  }

  async save(userId: string, refreshToken: string): Promise<void> {
    const ttl = this.jwtTokenService.getRefreshTokenTtlSeconds();
    const previousToken = await this.redisService.get(this.getUserKey(userId));

    await Promise.all([
      this.redisService.set(this.getUserKey(userId), refreshToken, ttl),
      this.redisService.set(this.getTokenKey(refreshToken), userId, ttl),
      previousToken && previousToken !== refreshToken
        ? this.redisService.delete(this.getTokenKey(previousToken))
        : Promise.resolve(),
    ]);
  }

  async getUserIdByToken(refreshToken: string): Promise<string | null> {
    return this.redisService.get<string>(this.getTokenKey(refreshToken));
  }

  async getLatestTokenForUser(userId: string): Promise<string | null> {
    return this.redisService.get<string>(this.getUserKey(userId));
  }

  private getUserKey(userId: string): string {
    return `${this.refreshTokenKeyPrefix}:user:${userId}`;
  }

  private getTokenKey(token: string): string {
    return `${this.refreshTokenKeyPrefix}:token:${token}`;
  }
}
