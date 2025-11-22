import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './strategies/google.strategy';
import { GoogleOAuthGuard } from './guards/google-auth.guard';

@Module({
  imports: [PassportModule.register({ defaultStrategy: 'google' })],
  providers: [GoogleStrategy, GoogleOAuthGuard],
  exports: [GoogleStrategy, GoogleOAuthGuard],
})
export class GoogleAuthModule {}
