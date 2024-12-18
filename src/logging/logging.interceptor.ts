import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { LoggingService } from './logging.service';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  constructor(private readonly loggingService: LoggingService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const method = request.method;
    const url = request.url;
    const now = Date.now();

    return next.handle().pipe(
      tap((responseBody) => {
        const executionTime = Date.now() - now;
        this.loggingService.createLog({
          method,
          url,
          executionTime,
          userId: request.user?.userId,
          statusCode: response.statusCode,
          requestBody: request.body,
          responseData: responseBody,
          headers: this.extractHeaders(request),
          userAgent: request.get('user-agent'),
          ip: request.ip,
        });
      }),
      catchError((error) => {
        this.loggingService.createLog({
          method,
          url,
          executionTime: Date.now() - now,
          userId: request.user?.userId,
          statusCode: error.status,
          requestBody: request.body,
          headers: this.extractHeaders(request),
          userAgent: request.get('user-agent'),
          ip: request.ip,
          error: error.message,
        });
        throw error;
      }),
    );
  }

  private extractHeaders(request: any): Record<string, any> {
    const headers = { ...request.headers };
    // Remove sensitive information
    delete headers.authorization;
    delete headers.cookie;
    return headers;
  }
}
