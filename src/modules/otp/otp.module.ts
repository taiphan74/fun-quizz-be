import { Module } from '@nestjs/common';
import { RedisModule } from '../../common/redis/redis.module';
import { MailModule } from '../../common/mail/mail.module';
import { OtpService } from './otp.service';

@Module({
  imports: [RedisModule, MailModule],
  providers: [OtpService],
  exports: [OtpService],
})
export class OtpModule {}
