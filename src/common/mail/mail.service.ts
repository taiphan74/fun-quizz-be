import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly mailerService: MailerService) {}

  async sendOtpEmail(to: string, otp: string): Promise<void> {
    await this.mailerService.sendMail({
      to,
      subject: 'Your password reset code',
      text: `Use this code to reset your password: ${otp}`,
      html: `<p>Use this code to reset your password:</p><h2>${otp}</h2>`,
    });
    this.logger.log(`Sent OTP email to ${to}`);
  }

  async sendEmailVerificationOtp(to: string, otp: string): Promise<void> {
    await this.mailerService.sendMail({
      to,
      subject: 'Verify your email address',
      text: `Use this code to verify your email: ${otp}`,
      html: `<p>Use this code to verify your email:</p><h2>${otp}</h2>`,
    });
    this.logger.log(`Sent verification OTP to ${to}`);
  }
}
