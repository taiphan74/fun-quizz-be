import { Injectable } from '@nestjs/common';
import { RedisService } from '../../../common/redis/redis.service';
import { AppConfigService } from '../../../config/app-config.service';
import { randomBytes } from 'crypto';

@Injectable()
export class RefreshTokenStore {
  private readonly refreshTokenKeyPrefix = 'refresh-token';
  private readonly refreshTokenTtlSeconds: number;

  constructor(
    private readonly redisService: RedisService,
    private readonly configService: AppConfigService,
  ) {
    this.refreshTokenTtlSeconds =
      this.configService.getJwtRefreshConfig().expiresInSeconds;
  }

  generateToken(): string {
    return randomBytes(64).toString('hex');
  }

  async issueForUser(userId: string): Promise<string> {
    const token = this.generateToken();
    await this.storeForUser(userId, token);
    return token;
  }

  async storeForUser(userId: string, refreshToken: string): Promise<void> {
    const previousToken = await this.redisService.get(this.getUserKey(userId));

    await Promise.all([
      this.redisService.set(
        this.getUserKey(userId),
        refreshToken,
        this.refreshTokenTtlSeconds,
      ),
      this.redisService.set(
        this.getTokenKey(refreshToken),
        userId,
        this.refreshTokenTtlSeconds,
      ),
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
