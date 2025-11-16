import { Module } from '@nestjs/common';
import { AnswersService } from './answers.service';
import { AnswersController } from './answers.controller';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';

@Module({
  controllers: [AnswersController],
  providers: [AnswersService, JwtAuthGuard, RolesGuard],
})
export class AnswersModule {}
