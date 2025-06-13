import { Body, Controller, Get, HttpCode, HttpStatus, Logger, Param, Put, Request, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

import { JwtAuthGuard } from "../../auth/strategies/jwt-auth.guard";
import { UsersService } from "../services/users.service";

// DTOs for request/response validation
export class UpdateProfileDto {
  firstName?: string;
  lastName?: string;
  email?: string;
}

export class ChangePasswordDto {
  currentPassword: string;
  newPassword: string;
}

@ApiTags("users")
@Controller("users")
export class UsersController {
  private readonly logger = new Logger(UsersController.name);

  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: "Get current user profile" })
  @ApiResponse({
    status: 200,
    description: "Current user profile retrieved successfully",
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
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 404, description: "User not found" })
  @ApiResponse({ status: 403, description: "Access denied" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Get("me")
  @UseGuards(JwtAuthGuard)
  async getCurrentUser(@Request() req) {
    this.logger.log(`Getting current user profile for user ID: ${req.user.id}`);
    const user = await this.usersService.findById(req.user.id);
    if (!user) {
      return { message: "User not found" };
    }

    // Do not return the password
    const { password, ...result } = user;
    return result;
  }

  @ApiOperation({ summary: "Update current user profile" })
  @ApiBody({ type: UpdateProfileDto })
  @ApiResponse({
    status: 200,
    description: "Profile updated successfully",
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
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 404, description: "User not found" })
  @ApiResponse({ status: 400, description: "Invalid request data" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Put("me")
  @UseGuards(JwtAuthGuard)
  async updateCurrentUser(@Request() req, @Body() updateProfileDto: UpdateProfileDto) {
    this.logger.log(`Updating profile for user ID: ${req.user.id}`);
    const updatedUser = await this.usersService.updateProfile(req.user.id, updateProfileDto);
    if (!updatedUser) {
      return { message: "User not found" };
    }

    // Do not return the password
    const { password, ...result } = updatedUser;
    return result;
  }

  @ApiOperation({ summary: "Change current user password" })
  @ApiBody({ type: ChangePasswordDto })
  @ApiResponse({
    status: 200,
    description: "Password changed successfully",
    schema: {
      type: "object",
      properties: {
        message: { type: "string" },
      },
    },
  })
  @ApiResponse({ status: 401, description: "Unauthorized or invalid current password" })
  @ApiResponse({ status: 404, description: "User not found" })
  @ApiResponse({ status: 400, description: "Invalid request data" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Put("me/password")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(@Request() req, @Body() changePasswordDto: ChangePasswordDto) {
    this.logger.log(`Changing password for user ID: ${req.user.id}`);
    await this.usersService.changePassword(req.user.id, changePasswordDto.currentPassword, changePasswordDto.newPassword);
    return { message: "Password changed successfully" };
  }

  @ApiOperation({ summary: "Retrieve user profile" })
  @ApiResponse({
    status: 200,
    description: "User profile retrieved successfully",
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
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 404, description: "User not found" })
  @ApiResponse({ status: 403, description: "Access denied" })
  @ApiResponse({ status: 400, description: "Invalid request" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Get("profile/:id")
  @UseGuards(JwtAuthGuard)
  async getProfile(@Param("id") id: string) {
    this.logger.log(`Getting profile for user ID: ${id}`);
    const user = await this.usersService.findById(id);
    if (!user) {
      return { message: "User not found" };
    }

    // Do not return the password
    const { password, ...result } = user;
    return result;
  }
}
