import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { LoggingInterceptor } from './logging/logging.interceptor';
import { LoggingService } from './logging/logging.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Validation pipe
  app.useGlobalPipes(new ValidationPipe());

  // Apply Logging Interceptor globally
  const loggingService = app.get(LoggingService);
  app.useGlobalInterceptors(new LoggingInterceptor(loggingService));

  // Swagger configuration
  const config = new DocumentBuilder()
    .setTitle('Banking API')
    .setDescription('Banking System API Documentation')
    .setVersion('1.0')
    .addTag('auth')
    .addBearerAuth(
      {
        description: 'Please enter token in following format: Bearer <JWT>',
        name: 'Authorization',
        bearerFormat: 'Bearer',
        scheme: 'Bearer',
        type: 'http',
        in: 'Header',
      },
      'access-token', // This name here is important for references
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  // enable CORS
  app.enableCors();
  await app.listen(4000);
}
bootstrap();
