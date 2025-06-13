import { Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import * as argon2 from "argon2";

import { User } from "../../interfaces/user.interface";
import { DbServiceClient } from "./db-service.client";

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(private readonly dbServiceClient: DbServiceClient) {}

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

  async findByOAuth(provider: string, providerId: string): Promise<User | null> {
    try {
      const user = await this.dbServiceClient.findUserByOAuth(provider, providerId);
      return user;
    }
    catch (error) {
      this.logger.error(`Error finding user by OAuth: ${error.message}`);
      throw error;
    }
  }

  async validateUserCredentials(email: string, password: string): Promise<Omit<User, "password"> | null> {
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
        this.logger.warn(`Error verifying password with argon2: ${error.message}`);
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
      this.logger.log(`Hashing password: ${userData.password}`);
      const hashedPassword = await argon2.hash(userData.password);

      const user = await this.dbServiceClient.createUser({
        ...userData,
        password: hashedPassword,
      });

      return user;
    }
    catch (error) {
      this.logger.error(`Error creating user: ${error.message}`);
      throw error;
    }
  }

  async createOrUpdateOAuthUser(oauthUserData: any): Promise<User> {
    try {
      const user = await this.dbServiceClient.createOrUpdateOAuthUser(oauthUserData);
      return user;
    }
    catch (error) {
      this.logger.error(`Error creating/updating OAuth user: ${error.message}`);
      throw error;
    }
  }

  async updateProfile(userId: string, updateData: {
    firstName?: string;
    lastName?: string;
    email?: string;
  }): Promise<User | null> {
    try {
      // Find the user first to make sure they exist
      const existingUser = await this.findById(userId);
      if (!existingUser) {
        return null;
      }

      // Update user profile through db service
      const updatedUser = await this.dbServiceClient.updateUserProfile(userId, updateData);
      return updatedUser;
    }
    catch (error) {
      this.logger.error(`Error updating user profile: ${error.message}`);
      throw error;
    }
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {
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
        this.logger.warn(`Error verifying current password with argon2: ${error.message}`);
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
}
