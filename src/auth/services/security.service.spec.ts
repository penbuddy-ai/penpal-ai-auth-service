import { HttpException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

import { SecurityService } from "./security.service";

describe("securityService", () => {
  let service: SecurityService;

  beforeEach(() => {
    const config = {
      get: (key: string, def?: any) => {
        const map: Record<string, any> = {
          OAUTH_MAX_ATTEMPTS: 2,
          OAUTH_WINDOW_MS: 60_000,
          OAUTH_BLOCK_DURATION_MS: 60_000,
        };
        return map[key] ?? def;
      },
    } as unknown as ConfigService;

    service = new SecurityService(config);
  });

  it("checkRateLimit allows first attempts then blocks after limit", () => {
    const ip = "1.2.3.4";
    const ua = "jest";

    // first attempts should pass
    expect(() => service.checkRateLimit(ip, ua)).not.toThrow();
    expect(() => service.checkRateLimit(ip, ua)).not.toThrow();

    // exceeding should throw
    expect(() => service.checkRateLimit(ip, ua)).toThrow(HttpException);

    const status = service.getRateLimitStatus(ip, ua);
    expect(status.attempts).toBeGreaterThan(0);
  });

  it("getSecurityStats returns shape", () => {
    const stats = service.getSecurityStats();
    expect(stats).toHaveProperty("totalEvents");
    expect(stats).toHaveProperty("recentEvents");
  });
});
