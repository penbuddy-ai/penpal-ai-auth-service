import { Injectable, Logger } from "@nestjs/common";
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

      try {
        passwordMatches = await argon2.verify(user.password, password);
      }
      catch (error) {
        this.logger.warn(`Error verifying password: ${error.message}. Falling back to direct comparison.`);
        // Fallback to direct comparison in case of error
        passwordMatches = user.password === password;
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
}
