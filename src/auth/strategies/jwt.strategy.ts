import { Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";

import { AuthService } from "../services/auth.service";

type JwtPayload = {
  sub: string;
  email: string;
  roles: string[];
};

/**
 * Extraire le token JWT du cookie ou du header d'autorisation
 */
function extractJwtFromCookieOrHeader(req: Request) {
  // D'abord, essayer d'extraire du cookie auth_token
  const token = req.cookies?.auth_token;

  if (token) {
    return token;
  }

  // Sinon, utiliser la méthode standard d'extraction du header Authorization
  return ExtractJwt.fromAuthHeaderAsBearerToken()(req);
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    super({
      jwtFromRequest: extractJwtFromCookieOrHeader,
      ignoreExpiration: false,
      secretOrKey: configService.get<string>("JWT_SECRET") || "fallback_secret_for_development",
    });
  }

  async validate(payload: JwtPayload) {
    this.logger.log(`Validating JWT for user: ${payload.email}`);

    const user = await this.authService.validateUserById(payload.sub);
    if (!user) {
      throw new UnauthorizedException("User no longer exists");
    }

    return {
      id: payload.sub,
      email: payload.email,
      roles: payload.roles,
    };
  }
}
