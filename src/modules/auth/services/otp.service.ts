import { Injectable } from '@nestjs/common';
import { RedisService } from '../../../common/redis/redis.service';
import { generateNumericOtp } from '../../../common/algorithms/otp.util';
import { MailService } from '../../../common/mail/mail.service';

@Injectable()
export class OtpService {
  constructor(
    private readonly redisService: RedisService,
    private readonly mailService: MailService,
  ) {}

  private async createOtp(key: string, ttlSeconds: number): Promise<string> {
    const otp = generateNumericOtp();
    await this.redisService.set(key, otp, ttlSeconds);
    return otp;
  }

  async sendPasswordResetOtp(
    key: string,
    email: string,
    ttlSeconds: number,
  ): Promise<void> {
    const otp = await this.createOtp(key, ttlSeconds);
    await this.mailService.sendOtpEmail(email, otp);
  }

  async sendEmailVerificationOtp(
    key: string,
    email: string,
    ttlSeconds: number,
  ): Promise<void> {
    const otp = await this.createOtp(key, ttlSeconds);
    await this.mailService.sendEmailVerificationOtp(email, otp);
  }

  async getOtp(key: string): Promise<string | null> {
    return this.redisService.get<string>(key);
  }

  async deleteOtp(key: string): Promise<void> {
    await this.redisService.delete(key);
  }
}
