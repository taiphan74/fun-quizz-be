import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../types/jwt-payload.interface';
import type { User } from '@prisma/client';
import { UserResponseDto } from '../../users/user.dto';

type JwtSource =
  | Pick<User, 'id' | 'username' | 'email' | 'role'>
  | Pick<UserResponseDto, 'id' | 'username' | 'email' | 'role'>;

@Injectable()
export class JwtTokenService {
  constructor(private readonly jwtService: JwtService) {}

  generateAccessToken(user: JwtSource): string {
    const payload = this.buildPayload(user);
    return this.jwtService.sign(payload);
  }

  private buildPayload(user: JwtSource): JwtPayload {
    return {
      sub: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };
  }
}
