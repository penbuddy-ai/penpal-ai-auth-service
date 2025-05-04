import { Injectable, Logger } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";

import { User } from "../../interfaces/user.interface";
import { UsersService } from "../../users/services/users.service";

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<Omit<User, "password"> | null> {
    try {
      const user = await this.usersService.validateUserCredentials(email, password);
      if (!user) {
        return null;
      }
      return user;
    }
    catch (error) {
      this.logger.error(`Error validating user: ${error.message}`);
      throw error;
    }
  }

  async login(user: Omit<User, "password">) {
    const payload = {
      sub: user.id,
      email: user.email,
      roles: [user.role],
    };

    this.logger.log(`User logged in: ${user.email}`);

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }

  async validateUserById(userId: string): Promise<Omit<User, "password"> | null> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        return null;
      }
      return user;
    }
    catch (error) {
      this.logger.error(`Error validating user by ID: ${error.message}`);
      throw error;
    }
  }
}
