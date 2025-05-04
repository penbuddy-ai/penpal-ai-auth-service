import { Body, Controller, HttpCode, HttpStatus, Logger, Post, Request, UseGuards } from "@nestjs/common";
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

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
  async login(@Request() req: any) {
    this.logger.log(`Login attempt for user: ${req.user.email}`);
    return this.authService.login(req.user);
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
}
