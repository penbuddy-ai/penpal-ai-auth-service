import { INestApplication } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import * as request from "supertest";

import { AuthController } from "../src/auth/controllers/auth.controller";
import { AuthService } from "../src/auth/services/auth.service";
import { SecurityService } from "../src/auth/services/security.service";
import { LocalAuthGuard } from "../src/auth/strategies/local-auth.guard";
import { UsersService } from "../src/users/services/users.service";

describe("Auth e2e (no external services)", () => {
  let app: INestApplication;
  let _authService: jest.Mocked<AuthService>;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            login: jest.fn().mockResolvedValue({ access_token: "tkn", user: { id: "u1", email: "e@x.com" } }),
          },
        },
        { provide: UsersService, useValue: { createUser: jest.fn() } },
        {
          provide: SecurityService,
          useValue: {
            checkRateLimit: jest.fn(),
            logFailedAuth: jest.fn(),
            logSuccessfulAuth: jest.fn(),
            getSecurityStats: jest.fn().mockReturnValue({ totalEvents: 0, suspiciousIPs: 0, rateLimitedIPs: 0, recentEvents: [] }),
          },
        },
        {
          provide: LocalAuthGuard,
          useValue: {
            canActivate: (ctx: any) => {
              const req = ctx.switchToHttp().getRequest();
              req.user = { _id: "u1", email: "e@x.com", firstName: "A", lastName: "B", role: "user" };
              return true;
            },
          },
        },
      ],
    }).compile();

    app = module.createNestApplication();
    await app.init();
    _authService = module.get(AuthService) as jest.Mocked<AuthService>;
  });

  afterAll(async () => {
    await app.close();
  });

  it("POST /auth/register creates user (mocked)", async () => {
    // Mock usersService.createUser to return a user object
    const usersService = app.get(UsersService) as any;
    usersService.createUser.mockResolvedValue({ id: "u1", email: "e@x.com", firstName: "A", lastName: "B", role: "user", password: undefined });
    const res = await request(app.getHttpServer())
      .post("/auth/register")
      .send({ email: "e@x.com", password: "p", firstName: "A", lastName: "B" })
      .expect(201);
    expect(res.body.email).toBe("e@x.com");
  });
});
