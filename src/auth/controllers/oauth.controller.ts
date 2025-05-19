import { Body, Controller, Get, HttpCode, HttpStatus, Logger, Post, Query, Redirect, Res } from "@nestjs/common";
import { ApiBody, ApiOperation, ApiQuery, ApiResponse, ApiTags } from "@nestjs/swagger";
import { Response } from "express";

import { DbServiceClient } from "../../users/services/db-service.client";
import { AppleOAuthLoginDto, FacebookOAuthLoginDto, GithubOAuthLoginDto, GoogleOAuthLoginDto } from "../dto/oauth-login.dto";
import { OAuthService } from "../services/oauth.service";

@ApiTags("auth")
@Controller("auth/oauth")
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);

  constructor(
    private readonly oauthService: OAuthService,
    private readonly dbServiceClient: DbServiceClient,
  ) {}

  @ApiOperation({ summary: "Initier l'authentification Google OAuth" })
  @ApiResponse({ status: HttpStatus.FOUND, description: "Redirection vers Google" })
  @Get("google/login")
  @Redirect()
  async googleLogin() {
    this.logger.log("Initiating Google OAuth login");
    const url = await this.oauthService.getGoogleAuthUrl();
    return { url };
  }

  @ApiOperation({ summary: "Callback Google OAuth" })
  @ApiQuery({ name: "code", required: true, type: String })
  @ApiQuery({ name: "state", required: false, type: String })
  @ApiResponse({ status: HttpStatus.OK, description: "Authentication successful" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Get("google/callback")
  @Redirect()
  async googleCallback(
    @Query("code") code: string,
    @Query("state") state: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.logger.log(`Google OAuth callback received with code`);
    const authResult = await this.oauthService.handleGoogleOAuthCallback(code, state);

    const user = await this.dbServiceClient.findUserByEmail(authResult.user.email);

    const frontendUrl = `${this.oauthService.getFrontendRedirectUrl()}/auth/callback`;

    // Configure a secure cookie with the JWT token
    const cookieOptions = {
      httpOnly: true, // Prevent JavaScript on the client from accessing the cookie
      secure: process.env.NODE_ENV === "production", // Cookies sent only via HTTPS in production
      sameSite: "lax" as const, // Protection against CSRF while allowing redirects
      maxAge: 24 * 60 * 60 * 1000, // 24 hours (in milliseconds)
      path: "/", // Cookie available for the whole site
    };

    // Define the cookie with the JWT token
    response.cookie("auth_token", authResult.access_token, cookieOptions);

    // Encode user data for the URL - the frontend will parse this on callback
    const userDataParam = encodeURIComponent(JSON.stringify(user));

    // Redirect to the frontend with user data as a query parameter
    return {
      url: `${frontendUrl}?userData=${userDataParam}`,
      statusCode: HttpStatus.FOUND,
    };
  }

  @ApiOperation({ summary: "Connexion via Google OAuth (méthode alternative)" })
  @ApiBody({ type: GoogleOAuthLoginDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Connexion réussie",
    schema: {
      type: "object",
      properties: {
        access_token: {
          type: "string",
          example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        },
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
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("google")
  @HttpCode(HttpStatus.OK)
  async googleAuth(@Body() googleAuthData: GoogleOAuthLoginDto) {
    this.logger.log(`Manual Google OAuth login attempt for: ${googleAuthData.email}`);
    return this.oauthService.handleManualGoogleAuth(googleAuthData);
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
}
