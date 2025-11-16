import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { UserRole } from '../users/user-role.enum';
import {
  AccessTokenResponseDto,
  AuthResponseDto,
  LoginDto,
  RefreshTokenDto,
  RegisterDto,
} from './auth.dto';
import { toUserResponse } from '../users/user.mapper';
import { JwtTokenService } from './jwt-token.service';
import { RedisService } from '../../common/redis/redis.service';
import { JwtPayload } from './types/jwt-payload.interface';
import { PrismaService } from '../../common/prisma/prisma.service';

@Injectable()
export class AuthService {
  private readonly refreshTokenKeyPrefix = 'refresh-token';

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtTokenService: JwtTokenService,
    private readonly redisService: RedisService,
    private readonly prisma: PrismaService,
  ) {}

  async login(loginDto: LoginDto): Promise<AuthResponseDto> {
    const { usernameOrEmail, password } = loginDto;
    const user = await this.usersService.findByUsernameOrEmail(usernameOrEmail);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.hashPassword);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const userResponse = toUserResponse(user);
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = this.jwtTokenService.generateRefreshToken(user);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user: userResponse, accessToken, refreshToken };
  }

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const user = await this.usersService.create({
      ...registerDto,
      role: UserRole.USER,
    });
    const accessToken = this.jwtTokenService.generateAccessToken(user);
    const refreshToken = this.jwtTokenService.generateRefreshToken(user);
    await this.storeRefreshToken(user.id, refreshToken);
    return { user, accessToken, refreshToken };
  }

  async refreshToken(
    refreshTokenDto: RefreshTokenDto,
  ): Promise<AccessTokenResponseDto> {
    const { refreshToken } = refreshTokenDto;
    const payload = this.verifyRefreshToken(refreshToken);
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const storedRefreshToken = await this.redisService.get(
      this.getRefreshTokenKey(user.id),
    );

    if (!storedRefreshToken || storedRefreshToken !== refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const accessToken = this.jwtTokenService.generateAccessToken(user);
    await this.storeRefreshToken(user.id, refreshToken);

    return { accessToken };
  }

  private getRefreshTokenKey(userId: string): string {
    return `${this.refreshTokenKeyPrefix}:${userId}`;
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const ttl = this.jwtTokenService.getRefreshTokenTtlSeconds();
    await this.redisService.set(
      this.getRefreshTokenKey(userId),
      refreshToken,
      ttl,
    );
  }

  private verifyRefreshToken(refreshToken: string): JwtPayload {
    try {
      return this.jwtTokenService.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
