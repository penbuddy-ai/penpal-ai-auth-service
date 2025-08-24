import { HttpStatus, Logger } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";

import { DbServiceClient } from "../../users/services/db-service.client";
import { OAuthService } from "../services/oauth.service";
import { SecurityService } from "../services/security.service";
import { OAuthController } from "./oauth.controller";

describe("oAuthController", () => {
  let controller: OAuthController;
  let oauthService: jest.Mocked<OAuthService>;
  let securityService: jest.Mocked<SecurityService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        { provide: OAuthService, useValue: { getGoogleAuthUrl: jest.fn().mockResolvedValue("https://google"), handleGoogleOAuthCallback: jest.fn(), getFrontendRedirectUrl: jest.fn().mockReturnValue("http://localhost:5173") } },
        { provide: DbServiceClient, useValue: {} },
        { provide: SecurityService, useValue: { checkRateLimit: jest.fn(), validateOAuthRequest: jest.fn(), logFailedAuth: jest.fn(), logSuccessfulAuth: jest.fn(), getSecurityStats: jest.fn().mockResolvedValue({ totalEvents: 0 }) } },
        { provide: Logger, useValue: new Logger("OAuthControllerTest") },
      ],
    }).compile();

    controller = module.get<OAuthController>(OAuthController);
    oauthService = module.get(OAuthService) as jest.Mocked<OAuthService>;
    securityService = module.get(SecurityService) as jest.Mocked<SecurityService>;
  });

  it("googleLogin returns redirect url", async () => {
    const res = await controller.googleLogin({ headers: {} } as any, undefined);
    expect(res).toEqual({ url: "https://google" });
    expect(oauthService.getGoogleAuthUrl).toHaveBeenCalled();
  });

  it("googleCallback returns error redirect on error param", async () => {
    const result = await controller.googleCallback({ headers: {} } as any, { cookie: jest.fn() } as any, undefined, undefined, "access_denied", "Denied");
    expect(result.statusCode).toBe(HttpStatus.FOUND);
  });

  it("getSecurityStats delegates to service", async () => {
    const stats = await controller.getSecurityStats({ headers: {} } as any);
    expect(stats).toEqual({ totalEvents: 0 });
    expect(securityService.getSecurityStats).toHaveBeenCalled();
  });
});
