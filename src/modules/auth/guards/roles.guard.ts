import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { UserRole } from '../../users/user-role.enum';
import { JwtPayload } from '../types/jwt-payload.interface';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<{
      user?: JwtPayload;
      path?: string;
      method?: string;
    }>();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Missing authenticated user');
    }

    if (!requiredRoles.includes(user.role)) {
      // Debug log to inspect which routes are failing role checks

      console.log(
        'RolesGuard blocked request',
        JSON.stringify({
          path: request.path,
          method: request.method,
          userRole: user.role,
          requiredRoles,
        }),
      );
      throw new ForbiddenException('Insufficient role');
    }

    return true;
  }
}
