import { Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import * as argon2 from "argon2";

import { User } from "../../interfaces/user.interface";
import { DbServiceClient, SubscriptionInfo } from "./db-service.client";
import { NotificationServiceClient } from "./notification-service.client";

export type OAuthUserResult = {
  user: User;
  isNewUser: boolean;
};

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private readonly dbServiceClient: DbServiceClient,
    private readonly notificationServiceClient: NotificationServiceClient,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    try {
      const user = await this.dbServiceClient.findUserByEmail(email);
      return user;
    }
    catch (error) {
      this.logger.error(`Error finding user by email: ${error.message}`);
      throw error;
    }
  }

  async findById(id: string): Promise<User | null> {
    try {
      const user = await this.dbServiceClient.findUserById(id);
      return user;
    }
    catch (error) {
      this.logger.error(`Error finding user by ID: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get user with subscription information for /me endpoint
   * This enriches the basic user data with subscription details from payment service
   */
  async findByIdWithSubscription(id: string): Promise<User | null> {
    try {
      // Get basic user data
      const user = await this.dbServiceClient.findUserById(id);
      if (!user) {
        return null;
      }

      // Get subscription information (non-blocking)
      let subscriptionInfo: SubscriptionInfo | null = null;
      try {
        subscriptionInfo = await this.dbServiceClient.getSubscriptionStatus(id);
      }
      catch (error) {
        this.logger.warn(
          `Failed to fetch subscription for user ${id}: ${error.message}`,
        );
        // Don't fail the whole request if payment service is down
      }

      // Enrich user data with subscription info
      const enrichedUser: User = {
        ...user,
        subscriptionPlan: subscriptionInfo?.plan || null,
        subscriptionStatus: subscriptionInfo?.status || null,
        subscriptionTrialEnd: subscriptionInfo?.nextBillingDate || undefined,
        hasActiveSubscription: subscriptionInfo?.isActive || false,
        cancelAtPeriodEnd: subscriptionInfo?.cancelAtPeriodEnd || false,
      };

      return enrichedUser;
    }
    catch (error) {
      this.logger.error(
        `Error finding user by ID with subscription: ${error.message}`,
      );
      throw error;
    }
  }

  async findByOAuth(
    provider: string,
    providerId: string,
  ): Promise<User | null> {
    try {
      const user = await this.dbServiceClient.findUserByOAuth(
        provider,
        providerId,
      );
      return user;
    }
    catch (error) {
      // Log the error but don't throw it - return null for non-existent users
      this.logger.debug(`User not found by OAuth ${provider}:${providerId} - ${error.message}`);
      return null;
    }
  }

  async validateUserCredentials(
    email: string,
    password: string,
  ): Promise<Omit<User, "password"> | null> {
    try {
      const user = await this.findByEmail(email);

      if (!user || !user.password) {
        return null;
      }

      let passwordMatches = false;
      this.logger.log(`Verifying password: ${user.password} with ${password}`);
      try {
        passwordMatches = await argon2.verify(user.password, password);
      }
      catch (error) {
        this.logger.warn(
          `Error verifying password with argon2: ${error.message}`,
        );
        // Don't fallback to direct comparison as it will never match
        // (hash vs plain text)
        return null;
      }

      if (!passwordMatches) {
        return null;
      }

      const { password: _password, ...result } = user;
      return result;
    }
    catch (error) {
      this.logger.error(`Error validating user credentials: ${error.message}`);
      throw error;
    }
  }

  async createUser(userData: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
  }): Promise<User> {
    try {
      // Hash the password before sending to db-service
      const hashedPassword = await argon2.hash(userData.password);

      const user = await this.dbServiceClient.createUser({
        ...userData,
        password: hashedPassword,
      });

      // Send welcome email for new user
      if (user) {
        this.sendWelcomeEmailAsync(user, "email");
      }

      return user;
    }
    catch (error) {
      this.logger.error(`Error creating user: ${error.message}`);
      throw error;
    }
  }

  async createOrUpdateOAuthUser(oauthUserData: any): Promise<OAuthUserResult> {
    try {
      // First, check if user already exists
      const existingUser = await this.findByOAuth(
        oauthUserData.profile.provider,
        oauthUserData.profile.providerId,
      );

      const isNewUser = !existingUser;

      this.logger.log(`OAuth user ${isNewUser ? "creation" : "update"} for: ${oauthUserData.profile.email}`);

      // Create or update the user via the DB service
      const user = await this.dbServiceClient.createOrUpdateOAuthUser(oauthUserData);

      // If it's a new user, send welcome email
      if (isNewUser && user) {
        this.sendWelcomeEmailAsync(user, oauthUserData.profile.provider);
      }

      return {
        user,
        isNewUser,
      };
    }
    catch (error) {
      this.logger.error(`Error creating/updating OAuth user: ${error.message}`);
      throw error;
    }
  }

  /**
   * Send welcome email asynchronously (non-blocking)
   */
  private async sendWelcomeEmailAsync(user: User, provider: string = "email"): Promise<void> {
    // Run this asynchronously to not block the registration flow
    setImmediate(async () => {
      try {
        this.logger.log(`Sending welcome email for new user (${provider}): ${user.email}`);

        const emailSent = await this.notificationServiceClient.sendWelcomeEmail({
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          provider,
          userId: user._id,
        });

        if (emailSent) {
          this.logger.log(`Welcome email sent successfully for: ${user.email}`);
        }
        else {
          this.logger.warn(`Welcome email failed for: ${user.email}`);
        }
      }
      catch (error) {
        this.logger.error(`Error sending welcome email for ${user.email}: ${error.message}`);
        // Don't throw - welcome email failure shouldn't affect user registration
      }
    });
  }

  async updateProfile(
    userId: string,
    updateData: {
      firstName?: string;
      lastName?: string;
      email?: string;
    },
  ): Promise<User | null> {
    try {
      // Find the user first to make sure they exist
      const existingUser = await this.findById(userId);
      if (!existingUser) {
        return null;
      }

      // Update user profile through db service
      const updatedUser = await this.dbServiceClient.updateUserProfile(
        userId,
        updateData,
      );
      return updatedUser;
    }
    catch (error) {
      this.logger.error(`Error updating user profile: ${error.message}`);
      throw error;
    }
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    try {
      // Find the user and verify current password
      const user = await this.findById(userId);
      if (!user || !user.password) {
        throw new UnauthorizedException("Invalid user or password");
      }

      // Verify current password
      let passwordMatches = false;
      try {
        passwordMatches = await argon2.verify(user.password, currentPassword);
      }
      catch (error) {
        this.logger.warn(
          `Error verifying current password with argon2: ${error.message}`,
        );
        // Don't fallback to direct comparison as it will never match
        // (hash vs plain text)
        throw new UnauthorizedException("Error verifying current password");
      }

      if (!passwordMatches) {
        throw new UnauthorizedException("Current password is incorrect");
      }

      // Hash the new password
      const hashedNewPassword = await argon2.hash(newPassword);

      // Update password through db service
      await this.dbServiceClient.updateUserPassword(userId, hashedNewPassword);

      this.logger.log(`Password changed successfully for user: ${userId}`);
    }
    catch (error) {
      this.logger.error(`Error changing password: ${error.message}`);
      throw error;
    }
  }

  // Onboarding methods
  async saveOnboardingProgress(
    userId: string,
    progressData: any,
  ): Promise<any> {
    try {
      // Find the user first to make sure they exist
      const existingUser = await this.findById(userId);
      if (!existingUser) {
        throw new Error("User not found");
      }

      // Forward to db service
      return await this.dbServiceClient.saveOnboardingProgress(
        userId,
        progressData,
      );
    }
    catch (error) {
      this.logger.error(`Error saving onboarding progress: ${error.message}`);
      throw error;
    }
  }

  async completeOnboarding(userId: string, onboardingData: any): Promise<any> {
    try {
      // Find the user first to make sure they exist
      const existingUser = await this.findById(userId);
      if (!existingUser) {
        throw new Error("User not found");
      }

      // Forward to db service
      return await this.dbServiceClient.completeOnboarding(
        userId,
        onboardingData,
      );
    }
    catch (error) {
      this.logger.error(`Error completing onboarding: ${error.message}`);
      throw error;
    }
  }

  async getOnboardingStatus(userId: string): Promise<any> {
    try {
      // Find the user first to make sure they exist
      const existingUser = await this.findById(userId);
      if (!existingUser) {
        throw new Error("User not found");
      }

      // Forward to db service
      return await this.dbServiceClient.getOnboardingStatus(userId);
    }
    catch (error) {
      this.logger.error(`Error getting onboarding status: ${error.message}`);
      throw error;
    }
  }

  /**
   * Update user subscription information (called by payment service)
   */
  async updateUserSubscriptionInfo(
    userId: string,
    subscriptionData: {
      plan?: "monthly" | "yearly";
      status?: "trial" | "active" | "past_due" | "canceled" | "unpaid";
      trialEnd?: Date;
    },
  ): Promise<any> {
    try {
      // Find the user first to make sure they exist
      const existingUser = await this.findById(userId);
      if (!existingUser) {
        throw new Error("User not found");
      }

      // Forward subscription update to db service
      return await this.dbServiceClient.updateUserSubscriptionInfo(
        userId,
        subscriptionData,
      );
    }
    catch (error) {
      this.logger.error(
        `Error updating user subscription info: ${error.message}`,
      );
      throw error;
    }
  }

  /**
   * Get user metrics for monitoring
   * Returns aggregated user statistics for Prometheus metrics
   */
  async getUserMetrics(): Promise<{
    activeUsers: number;
    totalUsers: number;
    usersByLanguage: Record<string, number>;
    averageUserLevel: Record<string, number>;
  }> {
    try {
      return await this.dbServiceClient.getUserMetrics();
    }
    catch (error) {
      this.logger.error(`Error getting user metrics: ${error.message}`);
      throw error;
    }
  }
}
