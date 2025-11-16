import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Question } from './question.entity';
import { CreateQuestionDto, UpdateQuestionDto } from './question.dto';

@Injectable()
export class QuestionsService {
  constructor(
    @InjectRepository(Question)
    private readonly questionRepository: Repository<Question>,
  ) {}

  async create(createQuestionDto: CreateQuestionDto): Promise<Question> {
    const question = this.questionRepository.create(createQuestionDto);
    const saved = await this.questionRepository.save(question);
    return this.findQuestionEntity(saved.id, true);
  }

  async findAll(): Promise<Question[]> {
    return this.questionRepository.find({
      relations: { answers: true },
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: string): Promise<Question> {
    return this.findQuestionEntity(id, true);
  }

  async update(
    id: string,
    updateQuestionDto: UpdateQuestionDto,
  ): Promise<Question> {
    const question = await this.findQuestionEntity(id);
    Object.assign(question, updateQuestionDto);
    await this.questionRepository.save(question);
    return this.findQuestionEntity(id, true);
  }

  async remove(id: string): Promise<{ message: string; questionId: string }> {
    const question = await this.findQuestionEntity(id);
    await this.questionRepository.remove(question);
    return { message: 'Question removed', questionId: id };
  }

  private async findQuestionEntity(
    id: string,
    includeAnswers = false,
  ): Promise<Question> {
    const question = await this.questionRepository.findOne({
      where: { id },
      relations: includeAnswers ? { answers: true } : undefined,
    });

    if (!question) {
      throw new NotFoundException(`Question with id ${id} not found`);
    }

    return question;
  }
}
