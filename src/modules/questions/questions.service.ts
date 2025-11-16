import { Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma, Question } from '@prisma/client';
import { CreateQuestionDto, UpdateQuestionDto } from './question.dto';
import { PrismaService } from '../../common/prisma/prisma.service';

type QuestionWithAnswers = Prisma.QuestionGetPayload<{
  include: { answers: true };
}>;

@Injectable()
export class QuestionsService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    createQuestionDto: CreateQuestionDto,
  ): Promise<QuestionWithAnswers> {
    const saved = await this.prisma.question.create({
      data: createQuestionDto,
    });
    return this.findQuestionWithAnswers(saved.id);
  }

  async findAll(): Promise<QuestionWithAnswers[]> {
    return this.prisma.question.findMany({
      include: { answers: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(id: string): Promise<QuestionWithAnswers> {
    return this.findQuestionWithAnswers(id);
  }

  async update(
    id: string,
    updateQuestionDto: UpdateQuestionDto,
  ): Promise<QuestionWithAnswers> {
    await this.ensureQuestionExists(id);
    await this.prisma.question.update({
      where: { id },
      data: updateQuestionDto,
    });
    return this.findQuestionWithAnswers(id);
  }

  async remove(id: string): Promise<{ message: string; questionId: string }> {
    await this.ensureQuestionExists(id);
    await this.prisma.question.delete({ where: { id } });
    return { message: 'Question removed', questionId: id };
  }

  private async ensureQuestionExists(id: string): Promise<Question> {
    const question = await this.prisma.question.findUnique({
      where: { id },
    });

    if (!question) {
      throw new NotFoundException(`Question with id ${id} not found`);
    }

    return question;
  }

  private async findQuestionWithAnswers(
    id: string,
  ): Promise<QuestionWithAnswers> {
    const question = await this.prisma.question.findUnique({
      where: { id },
      include: { answers: true },
    });

    if (!question) {
      throw new NotFoundException(`Question with id ${id} not found`);
    }

    return question;
  }
}
