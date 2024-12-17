import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const auth = request.headers.authorization;

    console.log('Raw Authorization Header:', auth);

    // Ensure proper Bearer token format
    if (!auth || !auth.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid Bearer token');
    }

    // Extract and validate token format
    const token = auth.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('Token not provided');
    }

    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any) {
    console.log('JWT Guard handleRequest:', { err, user, info });

    if (err || !user) {
      throw new UnauthorizedException(
        'Authentication failed: ' + (info?.message || 'Invalid token'),
      );
    }
    return user;
  }
}
