import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from './env.validation';

@Injectable()
export class AppConfigService {
  constructor(
    private readonly configService: ConfigService<EnvironmentVariables, true>,
  ) {}

  get nodeEnv(): EnvironmentVariables['NODE_ENV'] {
    return this.configService.get<EnvironmentVariables['NODE_ENV']>(
      'NODE_ENV',
      'development',
    );
  }

  get port(): number {
    return this.configService.getOrThrow<number>('PORT');
  }

  get corsOrigins(): string[] {
    const origins = this.configService.getOrThrow<string>('CORS_ORIGINS');
    return origins
      .split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0);
  }

  getDatabaseConfig() {
    return {
      host: this.configService.getOrThrow<string>('DB_HOST'),
      port: this.configService.getOrThrow<number>('DB_PORT'),
      username: this.configService.getOrThrow<string>('DB_USER'),
      password: this.configService.getOrThrow<string>('DB_PASSWORD'),
      database: this.configService.getOrThrow<string>('DB_NAME'),
    };
  }

  getJwtConfig() {
    return {
      secret: this.configService.getOrThrow<string>('JWT_SECRET'),
      expiresIn: this.configService.getOrThrow<number>('JWT_EXPIRES_IN'),
    };
  }

  getJwtRefreshConfig() {
    return {
      secret: this.configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.getOrThrow<number>(
        'JWT_REFRESH_EXPIRES_IN',
      ),
    };
  }

  getRedisConfig() {
    return {
      host: this.configService.getOrThrow<string>('REDIS_HOST'),
      port: this.configService.getOrThrow<number>('REDIS_PORT'),
      username: this.configService.get<string>('REDIS_USERNAME'),
      password: this.configService.get<string>('REDIS_PASSWORD'),
      db: this.configService.getOrThrow<number>('REDIS_DB'),
    };
  }

  getGoogleOAuthConfig() {
    return {
      clientId: this.configService.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      clientSecret:
        this.configService.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      callbackUrl: this.configService.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      frontendRedirectUrl: this.configService.getOrThrow<string>(
        'GOOGLE_FRONTEND_REDIRECT_URL',
      ),
    };
  }

  getMailConfig() {
    return {
      host: this.configService.getOrThrow<string>('MAIL_HOST'),
      port: this.configService.getOrThrow<number>('MAIL_PORT'),
      user: this.configService.getOrThrow<string>('MAIL_USER'),
      password: this.configService.getOrThrow<string>('MAIL_PASSWORD'),
      from: this.configService.getOrThrow<string>('MAIL_FROM'),
    };
  }
}
