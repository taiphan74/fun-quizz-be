import {
  Controller,
  Get,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { JwtPayload } from '../auth/types/jwt-payload.interface';

@ApiTags('users/me')
@UseGuards(JwtAuthGuard)
@Controller('users/me')
export class UserProfileController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  @ApiOkResponse({ description: 'Authenticated user profile' })
  getProfile(@Req() req: Request) {
    const user = req.user as JwtPayload | undefined;
    if (!user) {
      throw new UnauthorizedException('User context missing');
    }
    return this.usersService.findOne(user.sub);
  }
}
