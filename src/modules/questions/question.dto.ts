import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateQuestionDto {
  @ApiProperty({ example: 'What is the meaning of life?' })
  @IsString()
  @IsNotEmpty()
  title: string;

  @ApiProperty({
    example: 'Provide the ultimate answer from the hitchhiker guide.',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ example: true, required: false, default: true })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean = true;
}

export class UpdateQuestionDto extends PartialType(CreateQuestionDto) {}
