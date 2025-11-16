import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateAnswerDto {
  @ApiProperty({ example: '42', description: 'Answer text' })
  @IsString()
  @IsNotEmpty()
  text: string;

  @ApiProperty({ example: true, default: false })
  @IsBoolean()
  @IsOptional()
  isCorrect?: boolean = false;
}

export class UpdateAnswerDto extends PartialType(CreateAnswerDto) {}
