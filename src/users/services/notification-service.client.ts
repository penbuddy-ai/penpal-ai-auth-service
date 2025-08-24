import { HttpService } from "@nestjs/axios";
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AxiosError } from "axios";
import { catchError, firstValueFrom, timeout } from "rxjs";

export type WelcomeEmailRequest = {
  email: string;
  firstName: string;
  lastName: string;
  provider: string;
  userId?: string;
};

export type NotificationResponse = {
  success: boolean;
  message: string;
  timestamp: Date;
};

@Injectable()
export class NotificationServiceClient {
  private readonly logger = new Logger(NotificationServiceClient.name);
  private readonly notificationServiceUrl: string;
  private readonly apiKey: string;
  private readonly serviceName = "auth-service";

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.notificationServiceUrl
      = this.configService.get<string>("NOTIFICATION_SERVICE_URL")
        || "http://localhost:3007/api/v1";
    this.apiKey
      = this.configService.get<string>("NOTIFY_SERVICE_API_KEY") || "";

    if (!this.apiKey) {
      this.logger.warn(
        "NOTIFY_SERVICE_API_KEY not set! Notification service requests will fail.",
      );
    }

    this.logger.log(`Notification service client configured for: ${this.notificationServiceUrl}`);
  }

  async sendWelcomeEmail(emailData: WelcomeEmailRequest): Promise<boolean> {
    const url = `${this.notificationServiceUrl}/notifications/welcome-email`;

    try {
      this.logger.log(`Sending welcome email request to notification service for: ${emailData.email}`);

      const { data } = await firstValueFrom(
        this.httpService
          .post<NotificationResponse>(url, emailData, {
            headers: this.getServiceHeaders(),
            timeout: 10000, // 10 seconds timeout
          })
          .pipe(
            timeout(15000), // 15 seconds total timeout including retries
            catchError((error: AxiosError) => {
              this.logger.error(
                `Error sending welcome email notification: ${error.message}`,
                error.stack,
              );

              // Log additional error details
              if (error.response) {
                this.logger.error(`Response status: ${error.response.status}`);
                this.logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
              }

              throw error;
            }),
          ),
      );

      if (data.success) {
        this.logger.log(`Welcome email request successful for: ${emailData.email}`);
        return true;
      }
      else {
        this.logger.warn(`Welcome email request failed for: ${emailData.email} - ${data.message}`);
        return false;
      }
    }
    catch (error) {
      this.logger.error(`Failed to send welcome email notification for ${emailData.email}: ${error.message}`);
      // Don't throw the error - we don't want email failures to break user registration
      return false;
    }
  }

  async checkNotificationServiceHealth(): Promise<boolean> {
    const url = `${this.notificationServiceUrl}/notifications/health`;

    try {
      const { data } = await firstValueFrom(
        this.httpService
          .get(url, {
            headers: this.getServiceHeaders(),
            timeout: 5000,
          })
          .pipe(
            timeout(10000),
            catchError((error: AxiosError) => {
              this.logger.warn(`Notification service health check failed: ${error.message}`);
              throw error;
            }),
          ),
      );

      const isHealthy = data.status === "healthy";
      this.logger.log(`Notification service health: ${data.status} (email: ${data.email_service})`);
      return isHealthy;
    }
    catch (error) {
      this.logger.warn(`Notification service health check failed: ${error.message}`);
      return false;
    }
  }

  private getServiceHeaders() {
    return {
      "Content-Type": "application/json",
      "X-API-Key": this.apiKey,
      "User-Agent": `${this.serviceName}/1.0`,
      "X-Service-Name": this.serviceName,
    };
  }
}
