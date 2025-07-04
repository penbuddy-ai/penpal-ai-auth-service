import { BadRequestException, Injectable, Logger, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import axios from "axios";
import { LRUCache } from "lru-cache";
import { Buffer } from "node:buffer";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { User } from "../../interfaces/user.interface";
import { UsersService } from "../../users/services/users.service";

type OAuthState = {
  state: string;
  codeVerifier: string;
  nonce: string;
  timestamp: number;
  redirectUrl?: string;
};

type GoogleTokenResponse = {
  access_token: string;
  id_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
};

type GoogleUserInfo = {
  sub: string;
  email: string;
  email_verified: boolean;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
};

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);
  private readonly googleClientId: string;
  private readonly googleClientSecret: string;
  private readonly googleRedirectUrl: string;
  private readonly stateStore: LRUCache<string, OAuthState>;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.googleClientId = this.configService.get<string>("GOOGLE_CLIENT_ID") || "";
    this.googleClientSecret = this.configService.get<string>("GOOGLE_CLIENT_SECRET") || "";
    this.googleRedirectUrl = this.configService.get<string>("GOOGLE_CALLBACK_URL") || "http://localhost:3000/api/v1/auth/oauth/google/callback";

    // Initialize secure state store with TTL
    this.stateStore = new LRUCache<string, OAuthState>({
      max: 1000, // Maximum number of states to store
      ttl: 1000 * 60 * 10, // 10 minutes TTL
    });

    if (!this.googleClientId || !this.googleClientSecret) {
      this.logger.warn("Google OAuth credentials not set! Google authentication will not work properly.");
    }
  }

  getFrontendRedirectUrl(): string {
    return this.configService.get<string>("FRONTEND_URL") || "http://localhost:5173";
  }

  /**
   * Génère l'URL d'authentification Google avec PKCE et sécurité renforcée
   */
  async getGoogleAuthUrl(redirectUrl?: string): Promise<string> {
    const state = this.generateSecureState();
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    const nonce = this.generateNonce();

    // Store state securely with all necessary data
    const oauthState: OAuthState = {
      state,
      codeVerifier,
      nonce,
      timestamp: Date.now(),
      redirectUrl,
    };

    this.stateStore.set(state, oauthState);

    const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuthUrl.searchParams.append("client_id", this.googleClientId);
    googleAuthUrl.searchParams.append("redirect_uri", this.googleRedirectUrl);
    googleAuthUrl.searchParams.append("response_type", "code");
    googleAuthUrl.searchParams.append("scope", "openid email profile");
    googleAuthUrl.searchParams.append("state", state);
    googleAuthUrl.searchParams.append("nonce", nonce);
    googleAuthUrl.searchParams.append("code_challenge", codeChallenge);
    googleAuthUrl.searchParams.append("code_challenge_method", "S256");
    googleAuthUrl.searchParams.append("access_type", "offline");
    googleAuthUrl.searchParams.append("prompt", "consent");
    googleAuthUrl.searchParams.append("include_granted_scopes", "true");

    this.logger.log("Generated secure Google OAuth URL with PKCE");
    return googleAuthUrl.toString();
  }

  /**
   * Handles the Google OAuth callback with comprehensive security validation
   */
  async handleGoogleOAuthCallback(code: string, state?: string): Promise<any> {
    try {
      // 1. Validate required parameters
      if (!code) {
        throw new BadRequestException("Authorization code is required");
      }

      if (!state) {
        throw new BadRequestException("State parameter is required");
      }

      // 2. Validate and retrieve stored state
      const storedState = this.validateAndRetrieveState(state);

      // 3. Exchange code for tokens with PKCE
      const tokenResponse = await this.exchangeCodeForTokens(code, storedState.codeVerifier);

      // 4. Verify and decode ID token
      const userInfo = await this.verifyAndDecodeIdToken(tokenResponse.id_token, storedState.nonce);

      // 5. Get additional user info from userinfo endpoint
      const detailedUserInfo = await this.getGoogleUserInfo(tokenResponse.access_token);

      // 6. Cross-validate user info
      this.validateUserInfoConsistency(userInfo, detailedUserInfo);

      this.logger.log(`Successfully validated Google OAuth for: ${userInfo.email}`);

      // 7. Process user authentication
      return this.handleGoogleCallback(detailedUserInfo);
    }
    catch (error) {
      this.logger.error(`Error processing Google OAuth callback: ${error.message}`, error.stack);
      // Clean up state on error
      if (state) {
        this.stateStore.delete(state);
      }
      throw error;
    }
  }

  /**
   * Validates and retrieves stored OAuth state
   */
  private validateAndRetrieveState(state: string): OAuthState {
    const storedState = this.stateStore.get(state);

    if (!storedState) {
      throw new UnauthorizedException("Invalid or expired OAuth state");
    }

    // Check timestamp to prevent replay attacks
    const maxAge = 1000 * 60 * 10; // 10 minutes
    if (Date.now() - storedState.timestamp > maxAge) {
      this.stateStore.delete(state);
      throw new UnauthorizedException("OAuth state has expired");
    }

    // Use timing-safe comparison for state validation
    const stateBuffer = Buffer.from(state, "utf8");
    const storedStateBuffer = Buffer.from(storedState.state, "utf8");

    if (!timingSafeEqual(stateBuffer, storedStateBuffer)) {
      throw new UnauthorizedException("OAuth state mismatch");
    }

    // Remove state after successful validation (one-time use)
    this.stateStore.delete(state);

    return storedState;
  }

  /**
   * Exchange authorization code for tokens using PKCE
   */
  private async exchangeCodeForTokens(code: string, codeVerifier: string): Promise<GoogleTokenResponse> {
    try {
      const tokenResponse = await axios.post("https://oauth2.googleapis.com/token", {
        code,
        client_id: this.googleClientId,
        client_secret: this.googleClientSecret,
        redirect_uri: this.googleRedirectUrl,
        grant_type: "authorization_code",
        code_verifier: codeVerifier,
      }, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: 10000, // 10 second timeout
      });

      if (!tokenResponse.data.access_token || !tokenResponse.data.id_token) {
        throw new UnauthorizedException("Invalid token response from Google");
      }

      return tokenResponse.data;
    }
    catch (error) {
      if (axios.isAxiosError(error)) {
        this.logger.error(`Google token exchange failed: ${error.response?.data?.error_description || error.message}`);
        throw new UnauthorizedException("Failed to exchange authorization code");
      }
      throw error;
    }
  }

  /**
   * Verify and decode Google ID token
   */
  private async verifyAndDecodeIdToken(idToken: string, expectedNonce: string): Promise<any> {
    try {
      // Get Google's public keys for token verification (for future full JWT verification)
      const _jwksResponse = await axios.get("https://www.googleapis.com/oauth2/v3/certs", {
        timeout: 5000,
      });

      // Decode token header to get key ID
      const tokenParts = idToken.split(".");
      if (tokenParts.length !== 3) {
        throw new UnauthorizedException("Invalid ID token format");
      }

      const _header = JSON.parse(Buffer.from(tokenParts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(tokenParts[1], "base64url").toString());

      // Basic payload validation
      if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") {
        throw new UnauthorizedException("Invalid token issuer");
      }

      if (payload.aud !== this.googleClientId) {
        throw new UnauthorizedException("Invalid token audience");
      }

      if (payload.exp < Date.now() / 1000) {
        throw new UnauthorizedException("Token has expired");
      }

      if (payload.nonce !== expectedNonce) {
        throw new UnauthorizedException("Nonce mismatch");
      }

      if (!payload.email_verified) {
        throw new UnauthorizedException("Email not verified by Google");
      }

      return payload;
    }
    catch (error) {
      this.logger.error(`ID token verification failed: ${error.message}`);
      throw new UnauthorizedException("Invalid ID token");
    }
  }

  /**
   * Get detailed user information from Google's userinfo endpoint
   */
  private async getGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    try {
      const userInfoResponse = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "User-Agent": "PenpalAI-Auth/1.0",
        },
        timeout: 5000,
      });

      return userInfoResponse.data;
    }
    catch (error) {
      this.logger.error(`Failed to get user info: ${error.message}`);
      throw new UnauthorizedException("Failed to retrieve user information");
    }
  }

  /**
   * Cross-validate user information from different sources
   */
  private validateUserInfoConsistency(idTokenPayload: any, userInfo: GoogleUserInfo): void {
    if (idTokenPayload.sub !== userInfo.sub) {
      throw new UnauthorizedException("User ID mismatch between token and userinfo");
    }

    if (idTokenPayload.email !== userInfo.email) {
      throw new UnauthorizedException("Email mismatch between token and userinfo");
    }

    if (!userInfo.email_verified) {
      throw new UnauthorizedException("Email not verified");
    }
  }

  /**
   * Handles a previously retrieved Google profile
   */
  async handleGoogleCallback(profile: GoogleUserInfo): Promise<any> {
    try {
      this.logger.log(`Processing Google OAuth callback for: ${profile.email}`);

      // Build the DTO for the DB API
      const oauthUserData = {
        profile: {
          provider: "google",
          providerId: profile.sub,
          email: profile.email,
          displayName: profile.name,
          photoURL: profile.picture,
        },
        firstName: profile.given_name,
        lastName: profile.family_name,
        nativeLanguageCode: profile.locale || null,
        learningLanguageCodes: [],
      };

      // Create or update the user via the UsersService
      const { user, isNewUser } = await this.usersService.createOrUpdateOAuthUser(oauthUserData);

      if (isNewUser) {
        this.logger.log(`New user registered via Google OAuth: ${user.email}`);
      }
      else {
        this.logger.log(`Existing user logged in via Google OAuth: ${user.email}`);
      }

      // Generate a JWT token for the user
      return this.generateToken(user);
    }
    catch (error) {
      this.logger.error(`Error handling Google OAuth callback: ${error.message}`, error.stack);
      throw error;
    }
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
      sub: user._id,
      email: user.email,
      roles: [user.role],
      iat: Math.floor(Date.now() / 1000),
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }

  /**
   * Generate cryptographically secure state parameter
   */
  private generateSecureState(): string {
    return randomBytes(32).toString("base64url");
  }

  /**
   * Generate PKCE code verifier
   */
  private generateCodeVerifier(): string {
    return randomBytes(32).toString("base64url");
  }

  /**
   * Generate PKCE code challenge
   */
  private generateCodeChallenge(codeVerifier: string): string {
    return createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
  }

  /**
   * Generate nonce for ID token validation
   */
  private generateNonce(): string {
    return randomBytes(16).toString("base64url");
  }

  /**
   * Clean up expired states (can be called periodically)
   */
  public cleanupExpiredStates(): void {
    // LRU cache handles this automatically with TTL
    this.logger.debug(`OAuth state store size: ${this.stateStore.size}`);
  }
}
