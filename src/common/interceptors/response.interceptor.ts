import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { Response } from 'express';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

type PlainObject = Record<string, unknown>;

interface StandardResponse<T> {
  statusCode: number;
  message: string;
  timestamp: string;
  data: T | PlainObject | null;
}

function hasMessage(
  data: PlainObject,
): data is PlainObject & { message: string } {
  return typeof data.message === 'string';
}

function isPlainObject(value: unknown): value is PlainObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept<T>(
    context: ExecutionContext,
    next: CallHandler<T>,
  ): Observable<StandardResponse<T>> {
    const httpContext = context.switchToHttp();
    const response = httpContext.getResponse<Response>();

    return next.handle().pipe(
      map((data: T) => {
        const statusCode = response.statusCode;

        let message = 'Success';
        let payload: T | PlainObject | null = data ?? null;

        if (isPlainObject(data) && hasMessage(data)) {
          const { message: extractedMessage, ...rest } = data;
          message = extractedMessage;
          payload = Object.keys(rest).length ? rest : null;
        }

        return {
          statusCode,
          message,
          timestamp: new Date().toISOString(),
          data: payload,
        };
      }),
    );
  }
}
