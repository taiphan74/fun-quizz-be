import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { AppConfigService } from '../../config/app-config.service';
import { MailService } from './mail.service';

@Module({
  imports: [
    MailerModule.forRootAsync({
      inject: [AppConfigService],
      useFactory: (config: AppConfigService) => {
        const mailConfig = config.getMailConfig();
        return {
          transport: {
            host: mailConfig.host,
            port: mailConfig.port,
            auth: {
              user: mailConfig.user,
              pass: mailConfig.password,
            },
          },
          defaults: {
            from: mailConfig.from,
          },
        };
      },
    }),
  ],
  providers: [MailService],
  exports: [MailerModule, MailService],
})
export class MailModule {}
