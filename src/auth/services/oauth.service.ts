import { Injectable, Logger, NotFoundException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";

import { User } from "../../interfaces/user.interface";
import { UsersService } from "../../users/services/users.service";

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async handleGoogleCallback(profile: any): Promise<any> {
    try {
      this.logger.log(`Processing Google OAuth callback for: ${profile.email}`);

      // Construire le DTO pour l'API DB
      const oauthUserData = {
        profile: {
          provider: "google",
          providerId: profile.id,
          email: profile.email,
          displayName: profile.displayName || `${profile.firstName} ${profile.lastName}`.trim(),
          photoURL: profile.picture,
        },
        nativeLanguageCode: null, // À compléter avec les données du profil si disponibles
        learningLanguageCodes: [], // À compléter avec les données du profil si disponibles
      };

      // Créer ou mettre à jour l'utilisateur via le UsersService
      const user = await this.usersService.createOrUpdateOAuthUser(oauthUserData);

      // Générer un token JWT pour l'utilisateur
      return this.generateToken(user);
    }
    catch (error) {
      this.logger.error(`Error handling Google OAuth callback: ${error.message}`, error.stack);
      throw error;
    }
  }

  // Cette méthode peut être étendue pour gérer d'autres fournisseurs OAuth (Facebook, Apple, GitHub, etc.)
  async handleOAuthCallback(provider: string, profile: any): Promise<any> {
    switch (provider) {
      case "google":
        return this.handleGoogleCallback(profile);
      default:
        throw new NotFoundException(`OAuth provider ${provider} not supported`);
    }
  }

  private generateToken(user: User) {
    const payload = {
      sub: user.id,
      email: user.email,
      roles: [user.role],
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }
}
