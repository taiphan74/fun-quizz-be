import { Module } from '@nestjs/common';
import { QuestionsService } from './questions.service';
import { QuestionsController } from './questions.controller';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';

@Module({
  controllers: [QuestionsController],
  providers: [QuestionsService, JwtAuthGuard, RolesGuard],
})
export class QuestionsModule {}
