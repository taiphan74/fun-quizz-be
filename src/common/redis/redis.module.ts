import { Global, Module } from '@nestjs/common';
import Redis from 'ioredis';
import { REDIS_CLIENT } from './redis.constants';
import { RedisService } from './redis.service';
import { AppConfigService } from '../../config/app-config.service';

@Global()
@Module({
  imports: [],
  providers: [
    {
      provide: REDIS_CLIENT,
      useFactory: (configService: AppConfigService) => {
        const redisConfig = configService.getRedisConfig();
        return new Redis({
          host: redisConfig.host,
          port: redisConfig.port,
          username: redisConfig.username,
          password: redisConfig.password,
          db: redisConfig.db,
        });
      },
      inject: [AppConfigService],
    },
    RedisService,
  ],
  exports: [REDIS_CLIENT, RedisService],
})
export class RedisModule {}
