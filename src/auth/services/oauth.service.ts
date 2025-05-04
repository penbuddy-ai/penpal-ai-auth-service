import { Injectable, Logger, NotFoundException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import axios from "axios";
import { randomBytes } from "node:crypto";

import { User } from "../../interfaces/user.interface";
import { UsersService } from "../../users/services/users.service";

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);
  private readonly googleClientId: string;
  private readonly googleClientSecret: string;
  private readonly googleRedirectUrl: string;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.googleClientId = this.configService.get<string>("GOOGLE_CLIENT_ID") || "";
    this.googleClientSecret = this.configService.get<string>("GOOGLE_CLIENT_SECRET") || "";
    this.googleRedirectUrl = this.configService.get<string>("GOOGLE_CALLBACK_URL") || "http://localhost:3000/api/v1/auth/oauth/google/callback";

    if (!this.googleClientId || !this.googleClientSecret) {
      this.logger.warn("Google OAuth credentials not set! Google authentication will not work properly.");
    }
  }

  getFrontendRedirectUrl(): string {
    return this.configService.get<string>("FRONTEND_URL") || "http://localhost:5173";
  }

  /**
   * Génère l'URL d'authentification Google
   */
  async getGoogleAuthUrl(): Promise<string> {
    const state = this.generateState();

    const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuthUrl.searchParams.append("client_id", this.googleClientId);
    googleAuthUrl.searchParams.append("redirect_uri", this.googleRedirectUrl);
    googleAuthUrl.searchParams.append("response_type", "code");
    googleAuthUrl.searchParams.append("scope", "email profile");
    googleAuthUrl.searchParams.append("state", state);
    googleAuthUrl.searchParams.append("access_type", "offline");
    googleAuthUrl.searchParams.append("prompt", "consent");

    return googleAuthUrl.toString();
  }

  /**
   * Handles the Google OAuth callback
   */
  async handleGoogleOAuthCallback(code: string, _state?: string): Promise<any> {
    try {
      // 1. Exchange the code for an access token
      const tokenResponse = await axios.post("https://oauth2.googleapis.com/token", {
        code,
        client_id: this.googleClientId,
        client_secret: this.googleClientSecret,
        redirect_uri: this.googleRedirectUrl,
        grant_type: "authorization_code",
      });

      const { access_token } = tokenResponse.data;

      // 2. Retrieve the profile information
      const profileResponse = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { Authorization: `Bearer ${access_token}` },
      });

      const profile = profileResponse.data;

      this.logger.log(`Retrieved Google profile for: ${profile.email}`);

      // 3. Créer ou mettre à jour l'utilisateur
      return this.handleGoogleCallback(profile);
    }
    catch (error) {
      this.logger.error(`Error processing Google OAuth callback: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Handles a previously retrieved Google profile
   */
  async handleGoogleCallback(profile: any): Promise<any> {
    try {
      this.logger.log(`Processing Google OAuth callback for: ${profile.email}`);

      // Build the DTO for the DB API
      const oauthUserData = {
        profile: {
          provider: "google",
          providerId: profile.sub || profile.id,
          email: profile.email,
          displayName: profile.name || profile.displayName || `${profile.given_name || profile.firstName} ${profile.family_name || profile.lastName}`.trim(),
          photoURL: profile.picture,
        },
        firstName: profile.given_name || profile.firstName,
        lastName: profile.family_name || profile.lastName,
        nativeLanguageCode: null, // To be completed with profile data if available
        learningLanguageCodes: [], // To be completed with profile data if available
      };

      // Create or update the user via the UsersService
      const user = await this.usersService.createOrUpdateOAuthUser(oauthUserData);

      // Generate a JWT token for the user
      return this.generateToken(user);
    }
    catch (error) {
      this.logger.error(`Error handling Google OAuth callback: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Handles manual Google authentication (via the API)
   */
  async handleManualGoogleAuth(googleAuthData: any): Promise<any> {
    return this.handleOAuthCallback("google", googleAuthData);
  }

  // This method can be extended to handle other OAuth providers (Facebook, Apple, GitHub, etc.)
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

  private generateState(): string {
    return randomBytes(16).toString("hex");
  }
}
