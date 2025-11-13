import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from '../users/user.entity';
import { JwtTokenService } from './jwt-token.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const expiresInConfig = config.get<string>('JWT_EXPIRES_IN', '3600');
        const expiresInNumber = Number(expiresInConfig);
        return {
          secret: config.get<string>('JWT_SECRET', 'changeme'),
          signOptions: {
            expiresIn: Number.isNaN(expiresInNumber)
              ? 3600
              : expiresInNumber,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtTokenService, JwtStrategy, JwtAuthGuard],
  exports: [AuthService, JwtTokenService, JwtAuthGuard],
})
export class AuthModule {}
