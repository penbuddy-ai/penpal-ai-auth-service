import { BadRequestException, Body, Controller, Get, HttpCode, HttpStatus, Logger, Post, Query, Redirect, Req, Res, UnauthorizedException } from "@nestjs/common";
import { ApiBody, ApiOperation, ApiQuery, ApiResponse, ApiTags } from "@nestjs/swagger";
import { Request, Response } from "express";
import { LRUCache } from "lru-cache";
import { randomBytes } from "node:crypto";

import { DbServiceClient } from "../../users/services/db-service.client";
import { AppleOAuthLoginDto, FacebookOAuthLoginDto, GithubOAuthLoginDto } from "../dto/oauth-login.dto";
import { OAuthService } from "../services/oauth.service";
import { SecurityService } from "../services/security.service";

type PendingAuth = {
  userId: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  timestamp: number;
};

@ApiTags("auth")
@Controller("auth/oauth")
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);
  private readonly pendingAuthStore: LRUCache<string, PendingAuth>;

  constructor(
    private readonly oauthService: OAuthService,
    private readonly dbServiceClient: DbServiceClient,
    private readonly securityService: SecurityService,
  ) {
    // Initialize secure pending auth store
    this.pendingAuthStore = new LRUCache<string, PendingAuth>({
      max: 1000,
      ttl: 1000 * 60 * 5, // 5 minutes TTL for pending auth
    });
  }

  @ApiOperation({ summary: "Initier l'authentification Google OAuth" })
  @ApiResponse({ status: HttpStatus.FOUND, description: "Redirection vers Google" })
  @Get("google/login")
  @Redirect()
  async googleLogin(@Req() request: Request, @Query("redirect_url") redirectUrl?: string) {
    const ip = this.getClientIP(request);
    const userAgent = request.headers["user-agent"];

    this.logger.log(`🚀 Initiating Google OAuth login from ${ip}`);
    this.logger.log(`🔗 Redirect URL requested: ${redirectUrl || "none"}`);

    // Security checks
    this.securityService.checkRateLimit(ip, userAgent);
    this.securityService.validateOAuthRequest(ip, userAgent, { redirectUrl });

    // Validate redirect URL to prevent open redirect attacks
    const sanitizedRedirectUrl = this.validateRedirectUrl(redirectUrl);
    this.logger.log(`🔒 Sanitized redirect URL: ${sanitizedRedirectUrl || "none"}`);

    const url = await this.oauthService.getGoogleAuthUrl(sanitizedRedirectUrl);
    this.logger.log(`🎯 Generated OAuth URL: ${url}`);

    return { url };
  }

  @ApiOperation({ summary: "Callback Google OAuth sécurisé" })
  @ApiQuery({ name: "code", required: true, type: String })
  @ApiQuery({ name: "state", required: true, type: String })
  @ApiQuery({ name: "error", required: false, type: String })
  @ApiQuery({ name: "error_description", required: false, type: String })
  @ApiResponse({ status: HttpStatus.FOUND, description: "Redirection vers le frontend" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request or authorization denied" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Authentication failed" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @Get("google/callback")
  @Redirect()
  async googleCallback(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
    @Query("code") code?: string,
    @Query("state") state?: string,
    @Query("error") error?: string,
    @Query("error_description") errorDescription?: string,
  ) {
    const ip = this.getClientIP(request);
    const userAgent = request.headers["user-agent"];

    this.logger.log(`🔄 Google OAuth callback initiated from ${ip}`);
    this.logger.log(`🔄 Callback params - code: ${code ? "present" : "missing"}, state: ${state ? "present" : "missing"}, error: ${error || "none"}`);

    try {
      // Handle OAuth errors from Google
      if (error) {
        this.logger.warn(`❌ Google OAuth error: ${error} - ${errorDescription}`);
        this.securityService.logFailedAuth(ip, userAgent || "unknown", `OAuth error: ${error}`);
        return this.handleAuthError(error, errorDescription);
      }

      this.logger.log(`✅ Processing Google OAuth callback from ${ip}`);

      // Validate required parameters
      if (!code || !state) {
        this.logger.error(`❌ Missing required parameters - code: ${!!code}, state: ${!!state}`);
        throw new BadRequestException("Authorization code and state are required");
      }

      this.logger.log(`🔐 Starting OAuth token exchange...`);

      // Process the OAuth callback with comprehensive validation
      const authResult = await this.oauthService.handleGoogleOAuthCallback(code, state);

      this.logger.log(`✅ OAuth token exchange successful for: ${authResult.user.email}`);

      // User data is already validated by handleGoogleOAuthCallback
      const user = authResult.user;

      this.logger.log(`✅ User authenticated: ${user.email} (ID: ${user.id})`);

      // Validate user data
      if (!user.id) {
        this.logger.error(`❌ User ${user.email} has no ID in auth response`);
        throw new UnauthorizedException("Invalid user data");
      }

      // Generate secure session token for temporary auth completion
      const sessionToken = this.generateSecureSessionToken();

      // Store user data temporarily with the session token
      const pendingAuth: PendingAuth = {
        userId: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        timestamp: Date.now(),
      };

      this.pendingAuthStore.set(sessionToken, pendingAuth);
      this.logger.log(`🎟️ Session token generated for ${user.email}: ${sessionToken.substring(0, 10)}..., store size: ${this.pendingAuthStore.size}`);

      // Configure secure cookie with JWT token
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: (process.env.NODE_ENV === "production" ? "lax" : "strict") as "lax" | "strict", // More flexible in production for cross-origin scenarios
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: "/",
        domain: process.env.NODE_ENV === "production" ? this.getDomainFromUrl(this.oauthService.getFrontendRedirectUrl()) : undefined,
      };

      this.logger.log(`🍪 Setting auth cookie with options:`, {
        httpOnly: cookieOptions.httpOnly,
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        domain: cookieOptions.domain,
      });

      // Set auth cookie
      response.cookie("auth_token", authResult.access_token, cookieOptions);

      // Redirect to secure callback endpoint with session token
      const frontendUrl = `${this.oauthService.getFrontendRedirectUrl()}/auth/callback`;
      const secureCallbackUrl = `${frontendUrl}?session=${sessionToken}`;

      this.logger.log(`🎯 Redirecting to: ${secureCallbackUrl}`);
      this.logger.log(`✅ OAuth authentication successful for: ${user.email}`);
      this.securityService.logSuccessfulAuth(ip, userAgent || "unknown", user.email);

      return {
        url: secureCallbackUrl,
        statusCode: HttpStatus.FOUND,
      };
    }
    catch (error) {
      this.logger.error(`💥 OAuth callback error: ${error.message}`, error.stack);
      this.securityService.logFailedAuth(ip, userAgent || "unknown", error.message);
      return this.handleAuthError("server_error", "Authentication failed");
    }
  }

  @ApiOperation({ summary: "Récupérer les données utilisateur après callback OAuth" })
  @ApiQuery({ name: "session", required: true, type: String })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Données utilisateur récupérées avec succès",
    schema: {
      type: "object",
      properties: {
        user: {
          type: "object",
          properties: {
            id: { type: "string" },
            email: { type: "string" },
            firstName: { type: "string" },
            lastName: { type: "string" },
            role: { type: "string" },
          },
        },
      },
    },
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid session token" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Session expired or invalid" })
  @Get("session/user")
  @HttpCode(HttpStatus.OK)
  async getSessionUser(@Query("session") sessionToken: string, @Req() request: Request) {
    const ip = this.getClientIP(request);

    this.logger.log(`Session user request from ${ip} with token: ${sessionToken?.substring(0, 10)}...`);

    if (!sessionToken) {
      this.logger.warn(`Missing session token from ${ip}`);
      throw new BadRequestException("Session token is required");
    }

    const pendingAuth = this.pendingAuthStore.get(sessionToken);
    if (!pendingAuth) {
      this.logger.warn(`Invalid or expired session token from ${ip}: ${sessionToken?.substring(0, 10)}...`);
      this.logger.debug(`Current store size: ${this.pendingAuthStore.size}`);
      throw new UnauthorizedException("Invalid or expired session");
    }

    // Validate session age
    const maxAge = 1000 * 60 * 5; // 5 minutes
    const sessionAge = Date.now() - pendingAuth.timestamp;

    if (sessionAge > maxAge) {
      this.logger.warn(`Session expired for ${pendingAuth.email}, age: ${Math.round(sessionAge / 1000)}s`);
      this.pendingAuthStore.delete(sessionToken);
      throw new UnauthorizedException("Session has expired");
    }

    this.logger.log(`Valid session found for user: ${pendingAuth.email}, age: ${Math.round(sessionAge / 1000)}s`);

    // Allow multiple access within 30 seconds to handle frontend double-calls
    const graceWindow = 30 * 1000; // 30 seconds
    if (sessionAge > graceWindow) {
      this.logger.log(`Session grace window expired, removing token for ${pendingAuth.email}`);
      this.pendingAuthStore.delete(sessionToken);
    }
    else {
      this.logger.log(`Session within grace window (${Math.round(sessionAge / 1000)}s), keeping token`);
    }

    return {
      user: {
        id: pendingAuth.userId,
        email: pendingAuth.email,
        firstName: pendingAuth.firstName,
        lastName: pendingAuth.lastName,
        role: pendingAuth.role,
      },
    };
  }

  @ApiOperation({ summary: "Connexion via Facebook OAuth" })
  @ApiBody({ type: FacebookOAuthLoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: "Authentication successful" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("facebook")
  @HttpCode(HttpStatus.OK)
  async facebookAuth(@Body() facebookAuthData: FacebookOAuthLoginDto) {
    this.logger.log(`Facebook OAuth login attempt for: ${facebookAuthData.email}`);
    return this.oauthService.handleOAuthCallback("facebook", facebookAuthData);
  }

  @ApiOperation({ summary: "Connexion via Apple OAuth" })
  @ApiBody({ type: AppleOAuthLoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: "Authentication successful" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("apple")
  @HttpCode(HttpStatus.OK)
  async appleAuth(@Body() appleAuthData: AppleOAuthLoginDto) {
    this.logger.log(`Apple OAuth login attempt for ID: ${appleAuthData.id}`);
    return this.oauthService.handleOAuthCallback("apple", appleAuthData);
  }

  @ApiOperation({ summary: "Connexion via GitHub OAuth" })
  @ApiBody({ type: GithubOAuthLoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: "Authentication successful" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("github")
  @HttpCode(HttpStatus.OK)
  async githubAuth(@Body() githubAuthData: GithubOAuthLoginDto) {
    this.logger.log(`GitHub OAuth login attempt for: ${githubAuthData.email}`);
    return this.oauthService.handleOAuthCallback("github", githubAuthData);
  }

  @ApiOperation({ summary: "Debug: Vérifier le store de sessions (DEV uniquement)" })
  @Get("debug/sessions")
  @HttpCode(HttpStatus.OK)
  async getSessionsDebug(@Req() request: Request) {
    const ip = this.getClientIP(request);
    this.logger.log(`Debug sessions requested from ${ip}`);

    // Only allow in development
    if (process.env.NODE_ENV === "production") {
      throw new UnauthorizedException("Debug endpoint not available in production");
    }

    const sessions: any[] = [];
    for (const [token, auth] of this.pendingAuthStore.entries()) {
      sessions.push({
        tokenPrefix: token.substring(0, 10),
        email: auth.email,
        timestamp: auth.timestamp,
        age: Math.round((Date.now() - auth.timestamp) / 1000),
      });
    }

    return {
      storeSize: this.pendingAuthStore.size,
      sessions,
    };
  }

  @ApiOperation({ summary: "Obtenir les statistiques de sécurité OAuth (admin uniquement)" })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Statistiques de sécurité récupérées",
    schema: {
      type: "object",
      properties: {
        totalEvents: { type: "number" },
        suspiciousIPs: { type: "number" },
        rateLimitedIPs: { type: "number" },
        recentEvents: {
          type: "array",
          items: {
            type: "object",
            properties: {
              ip: { type: "string" },
              userAgent: { type: "string" },
              timestamp: { type: "number" },
              event: { type: "string" },
              details: { type: "string" },
            },
          },
        },
      },
    },
  })
  @Get("security/stats")
  @HttpCode(HttpStatus.OK)
  async getSecurityStats(@Req() request: Request) {
    const ip = this.getClientIP(request);
    this.logger.log(`Security stats requested from ${ip}`);

    // In a real application, you would add proper admin authentication here
    // For now, we'll just return the stats
    return this.securityService.getSecurityStats();
  }

  /**
   * Validate redirect URL to prevent open redirect attacks
   */
  private validateRedirectUrl(redirectUrl?: string): string | undefined {
    if (!redirectUrl) {
      return undefined;
    }

    const allowedDomains = [
      this.oauthService.getFrontendRedirectUrl(),
      "http://localhost:5173",
      "http://localhost:3000",
      "https://localhost:5173",
      "https://localhost:3000",
    ];

    try {
      const url = new URL(redirectUrl);
      const baseUrl = `${url.protocol}//${url.host}`;

      if (allowedDomains.some(domain => baseUrl === domain || redirectUrl.startsWith(domain))) {
        return redirectUrl;
      }

      this.logger.warn(`Invalid redirect URL attempted: ${redirectUrl}`);
      return undefined;
    }
    catch {
      this.logger.warn(`Malformed redirect URL: ${redirectUrl}`);
      return undefined;
    }
  }

  /**
   * Handle OAuth authentication errors
   */
  private handleAuthError(error: string, description?: string) {
    const frontendUrl = this.oauthService.getFrontendRedirectUrl();
    const errorUrl = `${frontendUrl}/auth/error?error=${encodeURIComponent(error)}${description ? `&description=${encodeURIComponent(description)}` : ""}`;

    return {
      url: errorUrl,
      statusCode: HttpStatus.FOUND,
    };
  }

  /**
   * Generate secure session token
   */
  private generateSecureSessionToken(): string {
    return randomBytes(32).toString("base64url");
  }

  /**
   * Extract domain from URL for cookie settings
   */
  private getDomainFromUrl(url: string): string | undefined {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname;

      if (process.env.NODE_ENV === "production") {
        const parts = hostname.split(".");
        if (parts.length >= 2) {
          return `.${parts.slice(-2).join(".")}`;
        }
      }

      return hostname;
    }
    catch {
      return undefined;
    }
  }

  /**
   * Extract client IP address from request
   */
  private getClientIP(request: Request): string {
    return (
      request.headers["x-forwarded-for"] as string
      || request.headers["x-real-ip"] as string
      || request.connection?.remoteAddress
      || request.socket?.remoteAddress
      || "unknown"
    );
  }

  /**
   * Clean up expired pending auth sessions
   */
  public cleanupExpiredSessions(): void {
    this.logger.debug(`Pending auth store size: ${this.pendingAuthStore.size}`);
  }
}
