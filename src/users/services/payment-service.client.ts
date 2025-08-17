import { HttpService } from "@nestjs/axios";
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AxiosError } from "axios";
import { catchError, firstValueFrom } from "rxjs";

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
export class PaymentServiceClient {
  private readonly logger = new Logger(PaymentServiceClient.name);
  private readonly paymentServiceUrl: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.paymentServiceUrl
      = this.configService.get<string>("PAYMENT_SERVICE_URL")
        || "http://localhost:3003";
  }

  /**
   * Get subscription status for a user
   * Returns null if payment service is unavailable to avoid blocking user login
   */
  async getSubscriptionStatus(
    userId: string,
  ): Promise<SubscriptionInfo | null> {
    const url = `${this.paymentServiceUrl}/subscriptions/user/${userId}/status`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            timeout: 5000, // 5 second timeout to avoid blocking
          })
          .pipe(
            catchError((error: AxiosError) => {
              // For 404 (no subscription), return empty array like DbServiceClient
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
        `Failed to get subscription status for user ${userId}, payment service may be down: ${error.message}`,
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
}
