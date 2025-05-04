import { Body, Controller, HttpCode, HttpStatus, Logger, Post, Request, Res, UseGuards } from "@nestjs/common";
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { Response } from "express";

import { UsersService } from "../../users/services/users.service";
import { RegisterDto } from "../dto/register.dto";
import { AuthService } from "../services/auth.service";
import { LocalAuthGuard } from "../strategies/local-auth.guard";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  @ApiOperation({ summary: "Connexion utilisateur" })
  @ApiBody({
    schema: {
      type: "object",
      properties: {
        email: {
          type: "string",
          example: "john.doe@example.com",
        },
        password: {
          type: "string",
          example: "password123",
        },
      },
      required: ["email", "password"],
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Utilisateur connecté avec succès",
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
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Identifiants invalides" })
  @Post("login")
  @UseGuards(LocalAuthGuard)
  @HttpCode(HttpStatus.OK)
  async login(@Request() req, @Res({ passthrough: true }) response: Response) {
    this.logger.log(`Login attempt for user: ${req.user.email}`);
    const authResult = await this.authService.login(req.user);

    // Configuration d'un cookie sécurisé avec le token JWT
    const cookieOptions = {
      httpOnly: true, // Empêche JavaScript côté client d'accéder au cookie
      secure: process.env.NODE_ENV === "production", // Cookies envoyés uniquement via HTTPS en production
      sameSite: "lax" as const, // Protection contre CSRF tout en permettant les redirections
      maxAge: 24 * 60 * 60 * 1000, // 24 heures (en millisecondes)
      path: "/", // Cookie disponible pour tout le site
    };

    // Définir le cookie avec le token JWT
    response.cookie("auth_token", authResult.access_token, cookieOptions);

    // Stocker les informations utilisateur de base dans un cookie non-HttpOnly
    response.cookie("user_info", JSON.stringify({
      id: authResult.user.id,
      email: authResult.user.email,
      firstName: authResult.user.firstName,
      lastName: authResult.user.lastName,
      role: authResult.user.role,
    }), {
      ...cookieOptions,
      httpOnly: false, // Le frontend doit pouvoir lire ces informations
    });

    // Retourner également le résultat d'authentification pour la compatibilité API
    return authResult;
  }

  @ApiOperation({ summary: "Inscription utilisateur" })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Utilisateur créé avec succès",
    schema: {
      type: "object",
      properties: {
        id: { type: "string" },
        firstName: { type: "string" },
        lastName: { type: "string" },
        email: { type: "string" },
        isEmailVerified: { type: "boolean" },
        provider: { type: "string" },
        role: { type: "string" },
      },
    },
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Données invalides" })
  @Post("register")
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    this.logger.log(`Registration attempt for user: ${registerDto.email}`);
    const user = await this.usersService.createUser({
      ...registerDto,
    });

    // Remove password from response
    const { password, ...result } = user;

    return result;
  }

  @ApiOperation({ summary: "Déconnexion" })
  @ApiResponse({ status: HttpStatus.OK, description: "Déconnexion réussie" })
  @Post("logout")
  @HttpCode(HttpStatus.OK)
  async logout(@Res({ passthrough: true }) response: Response) {
    this.logger.log("Logout endpoint called");

    // Effacer les cookies d'authentification
    response.clearCookie("auth_token");
    response.clearCookie("user_info");

    return { message: "Logout successful" };
  }
}
