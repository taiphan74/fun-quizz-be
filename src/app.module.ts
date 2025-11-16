import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { QuestionsModule } from './modules/questions/questions.module';
import { AnswersModule } from './modules/answers/answers.module';
import { RedisModule } from './common/redis/redis.module';
import { AppConfigModule } from './config/app-config.module';
import { PrismaModule } from './common/prisma/prisma.module';

@Module({
  imports: [
    AppConfigModule,
    PrismaModule,
    RedisModule,
    UsersModule,
    AuthModule,
    QuestionsModule,
    AnswersModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
