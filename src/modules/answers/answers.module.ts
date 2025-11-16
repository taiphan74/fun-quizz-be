import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Answer } from './answer.entity';
import { AnswersService } from './answers.service';
import { AnswersController } from './answers.controller';
import { Question } from '../questions/question.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';

@Module({
  imports: [TypeOrmModule.forFeature([Answer, Question])],
  controllers: [AnswersController],
  providers: [AnswersService, JwtAuthGuard, RolesGuard],
})
export class AnswersModule {}
