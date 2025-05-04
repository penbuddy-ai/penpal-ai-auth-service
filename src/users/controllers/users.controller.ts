import { Controller, Get, Logger, Param, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

import { JwtAuthGuard } from "../../auth/strategies/jwt-auth.guard";
import { UsersService } from "../services/users.service";

@ApiTags("users")
@Controller("users")
export class UsersController {
  private readonly logger = new Logger(UsersController.name);

  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: "Récupérer le profil utilisateur" })
  @ApiResponse({
    status: 200,
    description: "Profil utilisateur récupéré avec succès",
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
  @ApiResponse({ status: 401, description: "Non autorisé" })
  @ApiResponse({ status: 404, description: "Utilisateur non trouvé" })
  @ApiBearerAuth("JWT-auth")
  @Get("profile/:id")
  @UseGuards(JwtAuthGuard)
  async getProfile(@Param("id") id: string) {
    this.logger.log(`Getting profile for user ID: ${id}`);
    const user = await this.usersService.findById(id);
    if (!user) {
      return { message: "User not found" };
    }

    // Ne pas renvoyer le mot de passe
    const { password, ...result } = user;
    return result;
  }
}
