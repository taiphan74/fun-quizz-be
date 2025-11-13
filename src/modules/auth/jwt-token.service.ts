import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './types/jwt-payload.interface';
import { User } from '../users/user.entity';
import { UserResponseDto } from '../users/user.dto';

type JwtSource =
  | Pick<User, 'id' | 'username' | 'email'>
  | Pick<UserResponseDto, 'id' | 'username' | 'email'>;

@Injectable()
export class JwtTokenService {
  constructor(private readonly jwtService: JwtService) {}

  generateAccessToken(user: JwtSource): string {
    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      email: user.email,
    };
    return this.jwtService.sign(payload);
  }
}
