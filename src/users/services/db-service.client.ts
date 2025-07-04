import { HttpService } from "@nestjs/axios";
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AxiosError } from "axios";
import { catchError, firstValueFrom, of } from "rxjs";

import { User } from "../../interfaces/user.interface";

export type SubscriptionInfo = {
  hasSubscription: boolean;
  isActive: boolean;
  plan: "monthly" | "yearly" | null;
  status: "trial" | "active" | "past_due" | "canceled" | "unpaid" | null;
  trialActive: boolean;
  daysRemaining: number;
  nextBillingDate?: Date;
  cancelAtPeriodEnd?: boolean;
};

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
    this.dbServiceUrl
      = this.configService.get<string>("DB_SERVICE_URL")
        || "http://localhost:3001/api/v1";
    this.apiKey = this.configService.get<string>("DB_SERVICE_API_KEY") || "";

    if (!this.apiKey) {
      this.logger.warn(
        "DB_SERVICE_API_KEY not set! Inter-service authentication will fail.",
      );
    }
  }

  async createOrUpdateOAuthUser(oauthUserData: any): Promise<User> {
    const url = `${this.dbServiceUrl}/users/oauth`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .post(url, oauthUserData, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error creating/updating OAuth user: ${error.message}`,
                error.stack,
              );
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
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              if (error.response?.status === 404) {
                return [];
              }
              this.logger.error(
                `Error finding user by ID: ${error.message}`,
                error.stack,
              );
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

  async findUserByOAuth(
    provider: string,
    providerId: string,
  ): Promise<User | null> {
    const url = `${this.dbServiceUrl}/users/oauth/${provider}/${providerId}`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              if (error.response?.status === 404) {
                return of({ data: null });
              }
              this.logger.error(
                `Error finding user by OAuth: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to find user by OAuth: ${error.message}`);
      throw error;
    }
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const url = `${this.dbServiceUrl}/users/email/${email}`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              if (error.response?.status === 404) {
                return [];
              }
              this.logger.error(
                `Error finding user by email: ${error.message}`,
                error.stack,
              );
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
        this.httpService
          .post(url, userData, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error creating user: ${error.message}`,
                error.stack,
              );
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

  async updateUserProfile(
    userId: string,
    updateData: {
      firstName?: string;
      lastName?: string;
      email?: string;
    },
  ): Promise<User> {
    const url = `${this.dbServiceUrl}/users/${userId}/profile`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .patch(url, updateData, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error updating user profile: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to update user profile: ${error.message}`);
      throw error;
    }
  }

  async updateUserPassword(
    userId: string,
    hashedPassword: string,
  ): Promise<void> {
    const url = `${this.dbServiceUrl}/users/${userId}/password`;

    try {
      await firstValueFrom(
        this.httpService
          .patch(
            url,
            { password: hashedPassword },
            {
              headers: this.getServiceHeaders(),
            },
          )
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error updating user password: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );
    }
    catch (error) {
      this.logger.error(`Failed to update user password: ${error.message}`);
      throw error;
    }
  }

  // Onboarding methods
  async saveOnboardingProgress(
    userId: string,
    progressData: any,
  ): Promise<any> {
    const url = `${this.dbServiceUrl}/users/${userId}/onboarding/progress`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .patch(url, progressData, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error saving onboarding progress: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to save onboarding progress: ${error.message}`);
      throw error;
    }
  }

  async completeOnboarding(userId: string, onboardingData: any): Promise<any> {
    const url = `${this.dbServiceUrl}/users/${userId}/onboarding/complete`;

    try {
      // Convert language codes to ObjectIds
      const processedData = await this.processOnboardingData(onboardingData);

      const { data } = await firstValueFrom(
        this.httpService
          .patch(url, processedData, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error completing onboarding: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to complete onboarding: ${error.message}`);
      throw error;
    }
  }

  async getOnboardingStatus(userId: string): Promise<any> {
    const url = `${this.dbServiceUrl}/users/${userId}/onboarding/status`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error getting onboarding status: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to get onboarding status: ${error.message}`);
      throw error;
    }
  }

  /**
   * Convert language codes to ObjectIds by fetching from languages API
   */
  private async processOnboardingData(onboardingData: any): Promise<any> {
    if (
      !onboardingData.learningLanguages
      || !Array.isArray(onboardingData.learningLanguages)
    ) {
      return onboardingData;
    }

    try {
      // Fetch all languages from DB service
      const { data: languages } = await firstValueFrom(
        this.httpService
          .get(`${this.dbServiceUrl}/languages`, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error fetching languages: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      // Create a map of language codes to ObjectIds
      const languageMap = new Map();
      languages.forEach((lang: any) => {
        languageMap.set(lang.code, lang._id);
      });

      // Convert language codes to ObjectIds
      const learningLanguageIds = onboardingData.learningLanguages
        .map((code: string) => languageMap.get(code))
        .filter((id: any) => id !== undefined);

      return {
        ...onboardingData,
        learningLanguages: learningLanguageIds,
      };
    }
    catch (error) {
      this.logger.error(`Failed to process onboarding data: ${error.message}`);
      // Return original data if conversion fails
      return onboardingData;
    }
  }

  /**
   * Update user subscription information
   */
  async updateUserSubscriptionInfo(
    userId: string,
    subscriptionData: {
      plan?: "monthly" | "yearly";
      status?: "trial" | "active" | "past_due" | "canceled" | "unpaid";
      trialEnd?: Date;
    },
  ): Promise<any> {
    const url = `${this.dbServiceUrl}/users/${userId}/subscription`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .patch(url, subscriptionData, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error updating user subscription info: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(
        `Failed to update user subscription info: ${error.message}`,
      );
      throw error;
    }
  }

  /**
   * Get subscription status for a user from db-service
   * Returns null if db service is unavailable to avoid blocking user login
   */
  async getSubscriptionStatus(
    userId: string,
  ): Promise<SubscriptionInfo | null> {
    const url = `${this.dbServiceUrl}/subscriptions/user/${userId}/status/auth-service`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
            timeout: 5000, // 5 second timeout to avoid blocking
          })
          .pipe(
            catchError((error: AxiosError) => {
              // For 404 (no subscription), return empty array like other methods
              if (error.response?.status === 404) {
                return [];
              }

              this.logger.error(
                `Error getting subscription status for user ${userId}: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      // If error is empty array from 404, return default subscription info
      if (Array.isArray(error) && error.length === 0) {
        return {
          hasSubscription: false,
          isActive: false,
          plan: null,
          status: null,
          trialActive: false,
          daysRemaining: 0,
        };
      }

      this.logger.warn(
        `Failed to get subscription status for user ${userId}, db service may be down: ${error.message}`,
      );
      return null;
    }
  }

  /**
   * Check if user has active subscription (convenience method)
   */
  async hasActiveSubscription(userId: string): Promise<boolean> {
    const subscriptionInfo = await this.getSubscriptionStatus(userId);
    return subscriptionInfo?.isActive || false;
  }

  /**
   * Get user metrics for monitoring
   * Returns aggregated statistics about users
   */
  async getUserMetrics(): Promise<{
    activeUsers: number;
    totalUsers: number;
    usersByLanguage: Record<string, number>;
    averageUserLevel: Record<string, number>;
  }> {
    const url = `${this.dbServiceUrl}/users/metrics`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
          })
          .pipe(
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error getting user metrics: ${error.message}`,
                error.stack,
              );
              throw error;
            }),
          ),
      );

      return data;
    }
    catch (error) {
      this.logger.error(`Failed to get user metrics: ${error.message}`);
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
