import { HttpException, HttpStatus, Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { LRUCache } from "lru-cache";
import { createHash } from "node:crypto";

type RateLimitEntry = {
  count: number;
  firstAttempt: number;
  lastAttempt: number;
  blocked: boolean;
};

type SecurityEvent = {
  ip: string;
  userAgent: string;
  timestamp: number;
  event: string;
  details: string;
};

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);
  private readonly rateLimitStore: LRUCache<string, RateLimitEntry>;
  private readonly securityEvents: LRUCache<string, SecurityEvent[]>;
  private readonly suspiciousIPs: Set<string>;

  // Rate limiting configuration
  private readonly maxAttempts: number;
  private readonly windowMs: number;
  private readonly blockDurationMs: number;

  constructor(private readonly configService: ConfigService) {
    // Initialize rate limiting configuration
    this.maxAttempts = this.configService.get<number>("OAUTH_MAX_ATTEMPTS", 10);
    this.windowMs = this.configService.get<number>("OAUTH_WINDOW_MS", 15 * 60 * 1000); // 15 minutes
    this.blockDurationMs = this.configService.get<number>("OAUTH_BLOCK_DURATION_MS", 60 * 60 * 1000); // 1 hour

    // Initialize stores
    this.rateLimitStore = new LRUCache<string, RateLimitEntry>({
      max: 10000,
      ttl: this.blockDurationMs * 2, // Keep entries longer than block duration
    });

    this.securityEvents = new LRUCache<string, SecurityEvent[]>({
      max: 1000,
      ttl: 24 * 60 * 60 * 1000, // 24 hours
    });

    this.suspiciousIPs = new Set<string>();

    this.logger.log(`Security service initialized with rate limits: ${this.maxAttempts} attempts per ${this.windowMs}ms`);
  }

  /**
   * Check rate limit for OAuth operations
   */
  checkRateLimit(ip: string, userAgent?: string): void {
    const key = this.generateRateLimitKey(ip, userAgent);
    const now = Date.now();

    let entry = this.rateLimitStore.get(key);

    if (!entry) {
      // First attempt
      entry = {
        count: 1,
        firstAttempt: now,
        lastAttempt: now,
        blocked: false,
      };
      this.rateLimitStore.set(key, entry);
      return;
    }

    // Check if still within the rate limit window
    const windowStart = now - this.windowMs;

    if (entry.firstAttempt < windowStart) {
      // Reset the window
      entry.count = 1;
      entry.firstAttempt = now;
      entry.lastAttempt = now;
      entry.blocked = false;
      this.rateLimitStore.set(key, entry);
      return;
    }

    // Check if currently blocked
    if (entry.blocked && (now - entry.lastAttempt) < this.blockDurationMs) {
      this.logSecurityEvent(ip, userAgent || "unknown", "rate_limit_exceeded", `Blocked request from ${ip}, ${entry.count} attempts in window`);
      throw new HttpException("Too many OAuth attempts. Please wait before trying again.", HttpStatus.TOO_MANY_REQUESTS);
    }

    // Increment counter
    entry.count++;
    entry.lastAttempt = now;

    // Check if limit exceeded
    if (entry.count > this.maxAttempts) {
      entry.blocked = true;
      this.suspiciousIPs.add(ip);
      this.logSecurityEvent(ip, userAgent || "unknown", "rate_limit_blocked", `IP blocked after ${entry.count} attempts`);
      throw new HttpException("Too many OAuth attempts. Account temporarily blocked.", HttpStatus.TOO_MANY_REQUESTS);
    }

    this.rateLimitStore.set(key, entry);
  }

  /**
   * Validate OAuth request for security anomalies
   */
  validateOAuthRequest(ip: string, userAgent?: string, additionalParams?: Record<string, any>): void {
    // Check for suspicious patterns
    if (this.isSuspiciousIP(ip)) {
      this.logSecurityEvent(ip, userAgent || "unknown", "suspicious_ip", "Request from known suspicious IP");
      throw new UnauthorizedException("Request blocked for security reasons");
    }

    // Validate User-Agent
    if (this.isSuspiciousUserAgent(userAgent)) {
      this.logSecurityEvent(ip, userAgent || "unknown", "suspicious_user_agent", "Suspicious user agent pattern detected");
      // Log but don't block (could be legitimate bot)
      this.logger.warn(`Suspicious user agent from ${ip}: ${userAgent}`);
    }

    // Check for parameter injection attempts
    if (additionalParams) {
      this.validateParameters(ip, userAgent, additionalParams);
    }
  }

  /**
   * Log successful OAuth completion to track legitimate usage
   */
  logSuccessfulAuth(ip: string, userAgent: string, email: string): void {
    this.logSecurityEvent(ip, userAgent, "oauth_success", `Successful OAuth for ${email}`);

    // Remove from suspicious list if legitimate auth
    if (this.suspiciousIPs.has(ip)) {
      this.suspiciousIPs.delete(ip);
      this.logger.log(`Removed ${ip} from suspicious list after successful auth`);
    }
  }

  /**
   * Log failed OAuth attempt
   */
  logFailedAuth(ip: string, userAgent: string, reason: string): void {
    this.logSecurityEvent(ip, userAgent, "oauth_failure", reason);
  }

  /**
   * Get rate limit status for monitoring
   */
  getRateLimitStatus(ip: string, userAgent?: string): {
    attempts: number;
    remaining: number;
    resetTime: number;
    blocked: boolean;
  } {
    const key = this.generateRateLimitKey(ip, userAgent);
    const entry = this.rateLimitStore.get(key);

    if (!entry) {
      return {
        attempts: 0,
        remaining: this.maxAttempts,
        resetTime: Date.now() + this.windowMs,
        blocked: false,
      };
    }

    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Check if window has reset
    if (entry.firstAttempt < windowStart) {
      return {
        attempts: 0,
        remaining: this.maxAttempts,
        resetTime: now + this.windowMs,
        blocked: false,
      };
    }

    return {
      attempts: entry.count,
      remaining: Math.max(0, this.maxAttempts - entry.count),
      resetTime: entry.firstAttempt + this.windowMs,
      blocked: entry.blocked && (now - entry.lastAttempt) < this.blockDurationMs,
    };
  }

  /**
   * Generate unique key for rate limiting
   */
  private generateRateLimitKey(ip: string, userAgent?: string): string {
    const data = `${ip}:${userAgent || "unknown"}`;
    return createHash("sha256").update(data).digest("hex").substring(0, 16);
  }

  /**
   * Check if IP is known to be suspicious
   */
  private isSuspiciousIP(ip: string): boolean {
    // Check internal suspicious list
    if (this.suspiciousIPs.has(ip)) {
      return true;
    }

    // Check for known bad patterns (extend as needed)
    const suspiciousPatterns = [
      /^10\.0\.0\./, // Example: block certain internal ranges if exposed
      /^192\.168\./, // Example: block private ranges in production
    ];

    // Only apply private IP blocks in production
    if (process.env.NODE_ENV === "production") {
      return suspiciousPatterns.some(pattern => pattern.test(ip));
    }

    return false;
  }

  /**
   * Check for suspicious user agent patterns
   */
  private isSuspiciousUserAgent(userAgent?: string): boolean {
    if (!userAgent) {
      return true; // Missing user agent is suspicious
    }

    const suspiciousPatterns = [
      /curl/i,
      /wget/i,
      /python/i,
      /bot/i,
      /crawler/i,
      /spider/i,
      /^$/,
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  /**
   * Validate request parameters for injection attempts
   */
  private validateParameters(ip: string, userAgent: string | undefined, params: Record<string, any>): void {
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /onclick/i,
      /onerror/i,
      /eval\(/i,
      /expression\(/i,
      /url\(/i,
      /import\(/i,
    ];

    for (const [key, value] of Object.entries(params)) {
      if (typeof value === "string") {
        if (suspiciousPatterns.some(pattern => pattern.test(value))) {
          this.logSecurityEvent(ip, userAgent || "unknown", "parameter_injection", `Suspicious parameter detected: ${key}=${value}`);
          throw new UnauthorizedException("Invalid request parameters");
        }
      }
    }
  }

  /**
   * Log security events for monitoring
   */
  private logSecurityEvent(ip: string, userAgent: string, event: string, details: string): void {
    const securityEvent: SecurityEvent = {
      ip,
      userAgent,
      timestamp: Date.now(),
      event,
      details,
    };

    // Store events by IP for tracking patterns
    const existingEvents = this.securityEvents.get(ip) || [];
    existingEvents.push(securityEvent);
    this.securityEvents.set(ip, existingEvents);

    // Log for monitoring systems
    this.logger.warn(`Security event: ${event} from ${ip} - ${details}`, {
      ip,
      userAgent,
      event,
      details,
      timestamp: securityEvent.timestamp,
    });
  }

  /**
   * Get security statistics for monitoring
   */
  getSecurityStats(): {
    totalEvents: number;
    suspiciousIPs: number;
    rateLimitedIPs: number;
    recentEvents: SecurityEvent[];
  } {
    const now = Date.now();
    const last24Hours = now - (24 * 60 * 60 * 1000);

    let totalEvents = 0;
    const recentEvents: SecurityEvent[] = [];

    // Collect recent events
    for (const events of this.securityEvents.values()) {
      for (const event of events) {
        if (event.timestamp > last24Hours) {
          totalEvents++;
          if (recentEvents.length < 10) { // Limit to last 10 events
            recentEvents.push(event);
          }
        }
      }
    }

    // Sort recent events by timestamp
    recentEvents.sort((a, b) => b.timestamp - a.timestamp);

    return {
      totalEvents,
      suspiciousIPs: this.suspiciousIPs.size,
      rateLimitedIPs: this.rateLimitStore.size,
      recentEvents,
    };
  }

  /**
   * Clear security data (for testing or maintenance)
   */
  clearSecurityData(): void {
    this.rateLimitStore.clear();
    this.securityEvents.clear();
    this.suspiciousIPs.clear();
    this.logger.log("Security data cleared");
  }
}
