import { Body, Controller, HttpCode, HttpStatus, Logger, Post } from "@nestjs/common";
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

import { AppleOAuthLoginDto, FacebookOAuthLoginDto, GithubOAuthLoginDto, GoogleOAuthLoginDto } from "../dto/oauth-login.dto";
import { OAuthService } from "../services/oauth.service";

@ApiTags("auth")
@Controller("auth/oauth")
export class OAuthController {
  private readonly logger = new Logger(OAuthController.name);

  constructor(private readonly oauthService: OAuthService) {}

  @ApiOperation({ summary: "Connexion via Google OAuth" })
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
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Données invalides" })
  @Post("google")
  @HttpCode(HttpStatus.OK)
  async googleAuth(@Body() googleAuthData: GoogleOAuthLoginDto) {
    this.logger.log(`Google OAuth login attempt for: ${googleAuthData.email}`);
    return this.oauthService.handleOAuthCallback("google", googleAuthData);
  }

  @ApiOperation({ summary: "Connexion via Facebook OAuth" })
  @ApiBody({ type: FacebookOAuthLoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: "Connexion réussie" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Données invalides" })
  @Post("facebook")
  @HttpCode(HttpStatus.OK)
  async facebookAuth(@Body() facebookAuthData: FacebookOAuthLoginDto) {
    this.logger.log(`Facebook OAuth login attempt for: ${facebookAuthData.email}`);
    return this.oauthService.handleOAuthCallback("facebook", facebookAuthData);
  }

  @ApiOperation({ summary: "Connexion via Apple OAuth" })
  @ApiBody({ type: AppleOAuthLoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: "Connexion réussie" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Données invalides" })
  @Post("apple")
  @HttpCode(HttpStatus.OK)
  async appleAuth(@Body() appleAuthData: AppleOAuthLoginDto) {
    this.logger.log(`Apple OAuth login attempt for ID: ${appleAuthData.id}`);
    return this.oauthService.handleOAuthCallback("apple", appleAuthData);
  }

  @ApiOperation({ summary: "Connexion via GitHub OAuth" })
  @ApiBody({ type: GithubOAuthLoginDto })
  @ApiResponse({ status: HttpStatus.OK, description: "Connexion réussie" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Données invalides" })
  @Post("github")
  @HttpCode(HttpStatus.OK)
  async githubAuth(@Body() githubAuthData: GithubOAuthLoginDto) {
    this.logger.log(`GitHub OAuth login attempt for: ${githubAuthData.email}`);
    return this.oauthService.handleOAuthCallback("github", githubAuthData);
  }
}
