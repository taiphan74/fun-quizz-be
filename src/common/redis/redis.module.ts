import { Global, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { REDIS_CLIENT } from './redis.constants';
import { RedisService } from './redis.service';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: REDIS_CLIENT,
      useFactory: (configService: ConfigService) => {
        const host = configService.get<string>('REDIS_HOST', 'localhost');
        const port = parseInt(
          configService.get<string>('REDIS_PORT', '6379'),
          10,
        );
        const username = configService.get<string>('REDIS_USERNAME');
        const password = configService.get<string>('REDIS_PASSWORD');
        const db = parseInt(configService.get<string>('REDIS_DB', '0'), 10);

        return new Redis({
          host,
          port,
          username,
          password,
          db,
        });
      },
      inject: [ConfigService],
    },
    RedisService,
  ],
  exports: [REDIS_CLIENT, RedisService],
})
export class RedisModule {}
