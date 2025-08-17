import { INestApplication } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import * as request from "supertest";

import { OAuthController } from "../src/auth/controllers/oauth.controller";
import { OAuthService } from "../src/auth/services/oauth.service";
import { SecurityService } from "../src/auth/services/security.service";
import { DbServiceClient } from "../src/users/services/db-service.client";

describe("OAuth e2e (no external)", () => {
  let app: INestApplication;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        { provide: OAuthService, useValue: { getGoogleAuthUrl: jest.fn().mockResolvedValue("https://google"), handleGoogleOAuthCallback: jest.fn().mockResolvedValue({ access_token: "tkn", user: { id: "u1", email: "e@x.com", firstName: "A", lastName: "B", role: "user" } }), getFrontendRedirectUrl: jest.fn().mockReturnValue("http://localhost:5173") } },
        { provide: SecurityService, useValue: { checkRateLimit: jest.fn(), validateOAuthRequest: jest.fn(), logFailedAuth: jest.fn(), logSuccessfulAuth: jest.fn(), getSecurityStats: jest.fn().mockResolvedValue({ totalEvents: 0 }) } },
        { provide: DbServiceClient, useValue: {} },
      ],
    }).compile();

    app = module.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it("GET /auth/oauth/google/login returns redirect", async () => {
    const res = await request(app.getHttpServer()).get("/auth/oauth/google/login").expect(302);
    expect(res.headers.location).toBeDefined();
  });

  it("GET /auth/oauth/google/callback handles success", async () => {
    const res = await request(app.getHttpServer())
      .get("/auth/oauth/google/callback")
      .query({ code: "code", state: "state" })
      .expect(302);
    expect(res.headers.location).toContain("http://localhost:5173/auth/callback");
  });
});
