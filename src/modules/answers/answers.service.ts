import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Answer } from './answer.entity';
import { CreateAnswerDto, UpdateAnswerDto } from './answer.dto';
import { Question } from '../questions/question.entity';

@Injectable()
export class AnswersService {
  constructor(
    @InjectRepository(Answer)
    private readonly answerRepository: Repository<Answer>,
    @InjectRepository(Question)
    private readonly questionRepository: Repository<Question>,
  ) {}

  async create(
    questionId: string,
    createAnswerDto: CreateAnswerDto,
  ): Promise<Answer> {
    const question = await this.findQuestion(questionId);
    const answer = this.answerRepository.create({
      ...createAnswerDto,
      question,
    });
    return this.answerRepository.save(answer);
  }

  async findAll(questionId: string): Promise<Answer[]> {
    await this.ensureQuestionExists(questionId);
    return this.answerRepository.find({
      where: { questionId },
      order: { createdAt: 'ASC' },
    });
  }

  async update(
    questionId: string,
    answerId: string,
    updateAnswerDto: UpdateAnswerDto,
  ): Promise<Answer> {
    const answer = await this.findAnswer(questionId, answerId);
    Object.assign(answer, updateAnswerDto);
    return this.answerRepository.save(answer);
  }

  async remove(
    questionId: string,
    answerId: string,
  ): Promise<{ message: string; answerId: string }> {
    const answer = await this.findAnswer(questionId, answerId);
    await this.answerRepository.remove(answer);
    return { message: 'Answer removed', answerId };
  }

  private async ensureQuestionExists(questionId: string): Promise<void> {
    await this.findQuestion(questionId);
  }

  private async findQuestion(questionId: string): Promise<Question> {
    const question = await this.questionRepository.findOne({
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
    const answer = await this.answerRepository.findOne({
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
