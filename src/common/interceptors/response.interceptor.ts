import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const httpContext = context.switchToHttp();
    const response = httpContext.getResponse();

    return next.handle().pipe(
      map((data) => {
        const statusCode = response.statusCode;

        let message = 'Success';
        let payload = data;

        if (data && typeof data === 'object' && !Array.isArray(data)) {
          if (typeof (data as Record<string, unknown>).message === 'string') {
            message = (data as Record<string, string>).message;
            const { message: _message, ...rest } = data as Record<string, unknown>;
            payload = Object.keys(rest).length ? rest : null;
          }
        }

        return {
          statusCode,
          message,
          timestamp: new Date().toISOString(),
          data: payload ?? null,
        };
      }),
    );
  }
}
