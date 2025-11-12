import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { REDIS_CLIENT } from './redis.constants';

@Injectable()
export class RedisService implements OnModuleDestroy {
  constructor(@Inject(REDIS_CLIENT) private readonly client: Redis) {}

  getClient(): Redis {
    return this.client;
  }

  async get<T = string>(key: string): Promise<T | null> {
    const value = await this.client.get(key);
    return value as T | null;
  }

  async set(key: string, value: string, ttlInSeconds?: number): Promise<'OK'> {
    if (typeof ttlInSeconds === 'number') {
      return this.client.set(key, value, 'EX', ttlInSeconds);
    }

    return this.client.set(key, value);
  }

  async delete(key: string): Promise<number> {
    return this.client.del(key);
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
  }
}
