import { Injectable, NotFoundException } from '@nestjs/common';
import type { Answer, Question } from '@prisma/client';
import { CreateAnswerDto, UpdateAnswerDto } from './answer.dto';
import { PrismaService } from '../../common/prisma/prisma.service';

@Injectable()
export class AnswersService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    questionId: string,
    createAnswerDto: CreateAnswerDto,
  ): Promise<Answer> {
    await this.ensureQuestionExists(questionId);
    return this.prisma.answer.create({
      data: { ...createAnswerDto, questionId },
    });
  }

  async findAll(questionId: string): Promise<Answer[]> {
    await this.ensureQuestionExists(questionId);
    return this.prisma.answer.findMany({
      where: { questionId },
      orderBy: { createdAt: 'asc' },
    });
  }

  async update(
    questionId: string,
    answerId: string,
    updateAnswerDto: UpdateAnswerDto,
  ): Promise<Answer> {
    const answer = await this.findAnswer(questionId, answerId);
    return this.prisma.answer.update({
      where: { id: answer.id },
      data: updateAnswerDto,
    });
  }

  async remove(
    questionId: string,
    answerId: string,
  ): Promise<{ message: string; answerId: string }> {
    const answer = await this.findAnswer(questionId, answerId);
    await this.prisma.answer.delete({ where: { id: answer.id } });
    return { message: 'Answer removed', answerId };
  }

  private async ensureQuestionExists(questionId: string): Promise<void> {
    await this.findQuestion(questionId);
  }

  private async findQuestion(questionId: string): Promise<Question> {
    const question = await this.prisma.question.findUnique({
      where: { id: questionId },
    });

    if (!question) {
      throw new NotFoundException(`Question with id ${questionId} not found`);
    }

    return question;
  }

  private async findAnswer(
    questionId: string,
    answerId: string,
  ): Promise<Answer> {
    const answer = await this.prisma.answer.findFirst({
      where: { id: answerId, questionId },
    });

    if (!answer) {
      throw new NotFoundException(
        `Answer ${answerId} not found for question ${questionId}`,
      );
    }

    return answer;
  }
}
