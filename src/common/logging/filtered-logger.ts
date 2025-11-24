import { ConsoleLogger } from '@nestjs/common';

export class FilteredLogger extends ConsoleLogger {
  override error(message: any, stack?: string, context?: string): void {
    if (
      typeof message === 'string' &&
      message.includes('Transporter is ready') &&
      context === 'MailerService'
    ) {
      return this.log(message, context);
    }

    super.error(message, stack, context);
  }
}
