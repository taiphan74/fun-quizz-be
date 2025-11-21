import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { AppConfigService } from './config/app-config.service';
import cookieParser from 'cookie-parser';
import { FilteredLogger } from './common/logging/filtered-logger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: new FilteredLogger(),
  });
  const reflector = app.get(Reflector);
  const appConfigService = app.get(AppConfigService);

  console.log('CORS origins:', appConfigService.corsOrigins);

  app.use(helmet());
  app.use(cookieParser());
  app.enableCors({
    origin: appConfigService.corsOrigins,
    credentials: true,
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );
  app.useGlobalInterceptors(
    new ClassSerializerInterceptor(reflector),
    new ResponseInterceptor(),
  );

  if (process.env.NODE_ENV === 'development') {
    const config = new DocumentBuilder()
      .setTitle('Fun Quizz')
      .setDescription('The Fun Quizz API description')
      .setVersion('1.0')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);
  }

  await app.listen(process.env.PORT ?? 3000);
  console.log(`🚀 Server running on port ${process.env.PORT ?? 3000}`);
}

void bootstrap();
