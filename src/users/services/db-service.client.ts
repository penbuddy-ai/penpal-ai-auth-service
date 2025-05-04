import { HttpService } from "@nestjs/axios";
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AxiosError } from "axios";
import { catchError, firstValueFrom } from "rxjs";

import { User } from "../../interfaces/user.interface";

@Injectable()
export class DbServiceClient {
  private readonly logger = new Logger(DbServiceClient.name);
  private readonly dbServiceUrl: string;
  private readonly apiKey: string;
  private readonly serviceName = "auth-service";

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.dbServiceUrl = this.configService.get<string>("DB_SERVICE_URL") || "http://localhost:3001";
    this.apiKey = this.configService.get<string>("DB_SERVICE_API_KEY") || "";

    if (!this.apiKey) {
      this.logger.warn("DB_SERVICE_API_KEY not set! Inter-service authentication will fail.");
    }
  }

  async createOrUpdateOAuthUser(oauthUserData: any): Promise<User> {
    const url = `${this.dbServiceUrl}/users/oauth`;

    try {
      const { data } = await firstValueFrom(
        this.httpService.post(url, oauthUserData, {
          headers: this.getServiceHeaders(),
        }).pipe(
          catchError((error: AxiosError) => {
            this.logger.error(`Error creating/updating OAuth user: ${error.message}`, error.stack);
            throw error;
          }),
        ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to create/update OAuth user: ${error.message}`);
      throw error;
    }
  }

  async findUserById(id: string): Promise<User | null> {
    const url = `${this.dbServiceUrl}/users/${id}`;

    try {
      const { data } = await firstValueFrom(
        this.httpService.get(url, {
          headers: this.getServiceHeaders(),
        }).pipe(
          catchError((error: AxiosError) => {
            if (error.response?.status === 404) {
              return [];
            }
            this.logger.error(`Error finding user by ID: ${error.message}`, error.stack);
            throw error;
          }),
        ),
      );

      return data;
    }
    catch (error) {
      if (error.length === 0) {
        return null;
      }
      this.logger.error(`Failed to find user by ID: ${error.message}`);
      throw error;
    }
  }

  async findUserByOAuth(provider: string, providerId: string): Promise<User | null> {
    const url = `${this.dbServiceUrl}/users/oauth/${provider}/${providerId}`;

    try {
      const { data } = await firstValueFrom(
        this.httpService.get(url, {
          headers: this.getServiceHeaders(),
        }).pipe(
          catchError((error: AxiosError) => {
            if (error.response?.status === 404) {
              return [];
            }
            this.logger.error(`Error finding user by OAuth: ${error.message}`, error.stack);
            throw error;
          }),
        ),
      );

      return data;
    }
    catch (error) {
      if (error.length === 0) {
        return null;
      }
      this.logger.error(`Failed to find user by OAuth: ${error.message}`);
      throw error;
    }
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const url = `${this.dbServiceUrl}/users/email/${email}`;

    try {
      const { data } = await firstValueFrom(
        this.httpService.get(url, {
          headers: this.getServiceHeaders(),
        }).pipe(
          catchError((error: AxiosError) => {
            if (error.response?.status === 404) {
              return [];
            }
            this.logger.error(`Error finding user by email: ${error.message}`, error.stack);
            throw error;
          }),
        ),
      );

      return data;
    }
    catch (error) {
      if (error.length === 0) {
        return null;
      }
      this.logger.error(`Failed to find user by email: ${error.message}`);
      throw error;
    }
  }

  async createUser(userData: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
  }): Promise<User> {
    const url = `${this.dbServiceUrl}/users`;

    try {
      const { data } = await firstValueFrom(
        this.httpService.post(url, userData, {
          headers: this.getServiceHeaders(),
        }).pipe(
          catchError((error: AxiosError) => {
            this.logger.error(`Error creating user: ${error.message}`, error.stack);
            throw error;
          }),
        ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to create user: ${error.message}`);
      throw error;
    }
  }

  private getServiceHeaders() {
    return {
      "x-api-key": this.apiKey,
      "x-service-name": this.serviceName,
    };
  }
}
