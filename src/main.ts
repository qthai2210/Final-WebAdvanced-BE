import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { LoggingInterceptor } from './logging/logging.interceptor';
import { LoggingService } from './logging/logging.service';
import { json, urlencoded } from 'express';

async function bootstrap() {
  // Add garbage collection optimization
  if (global.gc) {
    global.gc();
  }

  const app = await NestFactory.create(AppModule, {
    bodyParser: true,
    // Limit payload size
    rawBody: true,
  });

  app.use(json({ limit: '50mb' }));
  app.use(urlencoded({ limit: '50mb', extended: true }));

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

  // Get port from environment variable or use default
  const port = process.env.PORT || 10000;

  // Log port configuration
  console.log(`Application starting on port: ${port}`);

  await app.listen(port, '0.0.0.0', () => {
    console.log(`Application is running on: http://localhost:${port}`);
    console.log(`Swagger documentation: http://localhost:${port}/api`);
  });
}

// Add error handling for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Perform cleanup if necessary
  process.exit(1);
});

bootstrap().catch((err) => {
  console.error('Failed to start application:', err);
  process.exit(1);
});
