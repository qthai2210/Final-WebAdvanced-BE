import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtUtil {
  constructor(private jwtService: JwtService) {}

  decodeJwt<T = any>(token: string): T | null {
    try {
      // Remove 'Bearer ' if present
      const cleanToken = token.replace('Bearer ', '');
      return this.jwtService.decode(cleanToken) as T;
    } catch (error) {
      console.error('JWT decode error:', error);
      return null;
    }
  }

  verifyJwt<T = any>(token: string): T | null {
    try {
      const cleanToken = token.replace('Bearer ', '');
      return this.jwtService.verify(cleanToken) as T;
    } catch (error) {
      console.error('JWT verification error:', error);
      return null;
    }
  }
}
