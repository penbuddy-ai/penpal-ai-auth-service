import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";

import { UsersModule } from "../users/users.module";
import { AuthController } from "./controllers/auth.controller";
import { OAuthController } from "./controllers/oauth.controller";
import { AuthService } from "./services/auth.service";
import { OAuthService } from "./services/oauth.service";
import { SecurityService } from "./services/security.service";
import { JwtStrategy } from "./strategies/jwt.strategy";
import { LocalStrategy } from "./strategies/local.strategy";

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>("JWT_SECRET"),
        signOptions: {
          expiresIn: configService.get<string>("JWT_EXPIRES_IN") || "1d",
          issuer: "penpal-ai-auth-service",
        },
      }),
    }),
  ],
  controllers: [AuthController, OAuthController],
  providers: [AuthService, OAuthService, SecurityService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
