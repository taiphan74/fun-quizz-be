import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { UserProfileController } from './profile.controller';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';

@Module({
  controllers: [UsersController, UserProfileController],
  providers: [UsersService, JwtAuthGuard, RolesGuard],
  exports: [UsersService],
})
export class UsersModule {}
