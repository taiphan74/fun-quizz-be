import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiCreatedResponse, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { AnswersService } from './answers.service';
import { CreateAnswerDto, UpdateAnswerDto } from './answer.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../users/user.entity';

@ApiTags('answers')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@Controller('questions/:questionId/answers')
export class AnswersController {
  constructor(private readonly answersService: AnswersService) {}

  @Post()
  @ApiCreatedResponse({ description: 'Answer has been created' })
  create(
    @Param('questionId') questionId: string,
    @Body() createAnswerDto: CreateAnswerDto,
  ) {
    return this.answersService.create(questionId, createAnswerDto);
  }

  @Get()
  @ApiOkResponse({ description: 'List answers for question' })
  findAll(@Param('questionId') questionId: string) {
    return this.answersService.findAll(questionId);
  }

  @Patch(':answerId')
  @ApiOkResponse({ description: 'Answer has been updated' })
  update(
    @Param('questionId') questionId: string,
    @Param('answerId') answerId: string,
    @Body() updateAnswerDto: UpdateAnswerDto,
  ) {
    return this.answersService.update(questionId, answerId, updateAnswerDto);
  }

  @Delete(':answerId')
  @ApiOkResponse({ description: 'Answer has been removed' })
  remove(
    @Param('questionId') questionId: string,
    @Param('answerId') answerId: string,
  ) {
    return this.answersService.remove(questionId, answerId);
  }
}
