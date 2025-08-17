import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from "@nestjs/common";
import { Request, Response } from "express";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";

@Injectable()
export class HttpLoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger("HTTP");

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Only log in development environment
    if (process.env.NODE_ENV === "production") {
      return next.handle();
    }

    const ctx = context.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    const { method, url, body, query, params, headers } = request;
    const userAgent = headers["user-agent"] || "unknown";
    const ip = this.getClientIP(request);

    const startTime = Date.now();

    // Log incoming request
    this.logger.log(`[REQUEST] ${method} ${url} - ${ip} - ${userAgent}`);

    // Log request details if available
    if (Object.keys(query).length > 0) {
      this.logger.debug(`Query params: ${JSON.stringify(query)}`);
    }

    if (Object.keys(params).length > 0) {
      this.logger.debug(`Path params: ${JSON.stringify(params)}`);
    }

    // Log request body for POST/PUT/PATCH (but hide sensitive data)
    if (body && ["POST", "PUT", "PATCH"].includes(method)) {
      const sanitizedBody = this.sanitizeRequestBody(body);
      this.logger.debug(`Request Body: ${JSON.stringify(sanitizedBody)}`);
    }

    return next.handle().pipe(
      tap({
        next: (responseBody) => {
          const duration = Date.now() - startTime;
          const contentLength = response.get("content-length") || "0";

          // Log response
          this.logger.log(
            `[RESPONSE] ${method} ${url} - ${response.statusCode} - ${duration}ms - ${contentLength}b`,
          );

          // Log response body (sanitized)
          if (responseBody) {
            const sanitizedResponse = this.sanitizeResponseBody(responseBody);
            this.logger.debug(`Response Body: ${JSON.stringify(sanitizedResponse)}`);
          }
        },
        error: (error) => {
          const duration = Date.now() - startTime;

          this.logger.error(
            `[RESPONSE] ${method} ${url} - ${error.status || 500} - ${duration}ms - ERROR`,
          );

          this.logger.error(`Error: ${error.message}`);
        },
      }),
    );
  }

  /**
   * Extract client IP address from request
   */
  private getClientIP(request: Request): string {
    const xForwardedFor = request.headers["x-forwarded-for"];
    const xRealIp = request.headers["x-real-ip"];

    if (typeof xForwardedFor === "string") {
      return xForwardedFor.split(",")[0].trim();
    }

    if (typeof xRealIp === "string") {
      return xRealIp.trim();
    }

    return request.socket.remoteAddress || "unknown";
  }

  /**
   * Sanitize request body to hide sensitive information
   */
  private sanitizeRequestBody(body: any): any {
    if (!body || typeof body !== "object") {
      return body;
    }

    const sanitized = { ...body };
    const sensitiveFields = ["password", "token", "secret", "key", "authorization"];

    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = "[REDACTED]";
      }
    }

    return sanitized;
  }

  /**
   * Sanitize response body to hide sensitive information
   */
  private sanitizeResponseBody(body: any): any {
    if (!body || typeof body !== "object") {
      return body;
    }

    const sanitized = { ...body };
    const sensitiveFields = ["password", "access_token", "refresh_token", "token", "secret"];

    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = "[REDACTED]";
      }
    }

    // Handle nested user objects
    if (sanitized.user && typeof sanitized.user === "object") {
      sanitized.user = this.sanitizeResponseBody(sanitized.user);
    }

    return sanitized;
  }
}
