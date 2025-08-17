import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  Patch,
  Put,
  Request,
  UnauthorizedException,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import {
  IsArray,
  IsBoolean,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
} from "class-validator";

import { JwtAuthGuard } from "../../auth/strategies/jwt-auth.guard";
import { UsersService } from "../services/users.service";

// DTOs for request/response validation
export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;

  @IsOptional()
  @IsString()
  email?: string;
}

export class ChangePasswordDto {
  @IsString()
  currentPassword: string;

  @IsString()
  newPassword: string;
}

export class OnboardingDto {
  @IsString()
  preferredName: string;

  @IsArray()
  @IsString({ each: true })
  learningLanguages: string[];

  @IsObject()
  proficiencyLevels: Record<string, string>;

  @IsBoolean()
  onboardingCompleted: boolean;
}

export class OnboardingProgressDto {
  @IsOptional()
  @IsString()
  preferredName?: string;

  @IsOptional()
  @IsString()
  learningLanguage?: string;

  @IsOptional()
  @IsString()
  proficiencyLevel?: string;

  @IsOptional()
  @IsNumber()
  currentStep?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  completedSteps?: string[];
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
        subscriptionPlan: { type: "string", enum: ["monthly", "yearly"] },
        subscriptionStatus: {
          type: "string",
          enum: ["trial", "active", "past_due", "canceled", "unpaid"],
        },
        subscriptionTrialEnd: { type: "string", format: "date-time" },
        hasActiveSubscription: { type: "boolean" },
        cancelAtPeriodEnd: { type: "boolean" },
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
    const user = await this.usersService.findByIdWithSubscription(req.user.id);
    if (!user) {
      return { message: "User not found" };
    }

    // Do not return the password and convert _id to id for frontend consistency
    const { password, _id, ...userWithoutPassword } = user;
    return {
      id: _id, // Convert _id to id for frontend consistency
      ...userWithoutPassword,
    };
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
  async updateCurrentUser(
    @Request() req,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    this.logger.log(`Updating profile for user ID: ${req.user.id}`);
    const updatedUser = await this.usersService.updateProfile(
      req.user.id,
      updateProfileDto,
    );
    if (!updatedUser) {
      return { message: "User not found" };
    }

    // Do not return the password and convert _id to id for frontend consistency
    const { password, _id, ...userWithoutPassword } = updatedUser;
    return {
      id: _id, // Convert _id to id for frontend consistency
      ...userWithoutPassword,
    };
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
  @ApiResponse({
    status: 401,
    description: "Unauthorized or invalid current password",
  })
  @ApiResponse({ status: 404, description: "User not found" })
  @ApiResponse({ status: 400, description: "Invalid request data" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Put("me/password")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @Request() req,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    this.logger.log(`Changing password for user ID: ${req.user.id}`);
    await this.usersService.changePassword(
      req.user.id,
      changePasswordDto.currentPassword,
      changePasswordDto.newPassword,
    );
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

    // Do not return the password and convert _id to id for frontend consistency
    const { password, _id, ...userWithoutPassword } = user;
    return {
      id: _id, // Convert _id to id for frontend consistency
      ...userWithoutPassword,
    };
  }

  // Onboarding endpoints
  @ApiOperation({ summary: "Save user onboarding progress" })
  @ApiBody({ type: OnboardingProgressDto })
  @ApiResponse({
    status: 200,
    description: "Onboarding progress saved successfully",
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 400, description: "Invalid request data" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Patch("me/onboarding/progress")
  @UseGuards(JwtAuthGuard)
  async saveOnboardingProgress(
    @Request() req,
    @Body() progressDto: OnboardingProgressDto,
  ) {
    this.logger.log(`Saving onboarding progress for user: ${req.user.id}`);
    return this.usersService.saveOnboardingProgress(req.user.id, progressDto);
  }

  @ApiOperation({ summary: "Complete user onboarding" })
  @ApiBody({ type: OnboardingDto })
  @ApiResponse({
    status: 200,
    description: "Onboarding completed successfully",
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 400, description: "Invalid request data" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Patch("me/onboarding/complete")
  @UseGuards(JwtAuthGuard)
  async completeOnboarding(
    @Request() req,
    @Body() onboardingDto: OnboardingDto,
  ) {
    this.logger.log(`Completing onboarding for user: ${req.user.id}`);
    return this.usersService.completeOnboarding(req.user.id, onboardingDto);
  }

  @ApiOperation({ summary: "Check user onboarding status" })
  @ApiResponse({
    status: 200,
    description: "Onboarding status retrieved",
    schema: {
      type: "object",
      properties: {
        needsOnboarding: { type: "boolean" },
        currentStep: { type: "string", nullable: true },
      },
    },
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @ApiBearerAuth("JWT-auth")
  @Get("me/onboarding/status")
  @UseGuards(JwtAuthGuard)
  async getOnboardingStatus(@Request() req) {
    this.logger.log(`Checking onboarding status for user: ${req.user.id}`);
    return this.usersService.getOnboardingStatus(req.user.id);
  }

  // Internal API for payment service
  @ApiOperation({ summary: "Update user subscription info (Internal API)" })
  @ApiResponse({
    status: 200,
    description: "User subscription updated successfully",
  })
  @ApiResponse({ status: 404, description: "User not found" })
  @ApiResponse({ status: 401, description: "Service not authorized" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  @Patch(":userId/subscription")
  async updateUserSubscription(
    @Param("userId") userId: string,
    @Body()
    subscriptionData: {
      plan?: "monthly" | "yearly";
      status?: "trial" | "active" | "past_due" | "canceled" | "unpaid";
      trialEnd?: Date;
    },
    @Request() req,
  ) {
    // Validate that this is a service-to-service call
    const serviceKey = req.headers["x-service-key"];
    const serviceName = req.headers["x-service-name"];

    if (
      !serviceKey
      || serviceKey !== process.env.SERVICE_API_KEY
      || serviceName !== "payment-service"
    ) {
      this.logger.warn(
        `Unauthorized service call from ${serviceName || "unknown"}`,
      );
      throw new UnauthorizedException("Service not authorized");
    }

    this.logger.log(
      `Updating subscription for user ${userId} from payment service`,
    );
    return this.usersService.updateUserSubscriptionInfo(
      userId,
      subscriptionData,
    );
  }

  /**
   * Get user metrics for monitoring
   * Endpoint used by monitoring service to collect user statistics
   */
  @Get("metrics")
  @ApiOperation({ summary: "Get user metrics for monitoring" })
  @ApiResponse({
    status: 200,
    description: "User metrics retrieved successfully",
  })
  async getUserMetrics() {
    const metrics = await this.usersService.getUserMetrics();
    return metrics;
  }
}
