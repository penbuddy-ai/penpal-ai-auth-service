import { Test, TestingModule } from "@nestjs/testing";

import { UsersService } from "../../users/services/users.service";
import { AuthService } from "../services/auth.service";
import { SecurityService } from "../services/security.service";
import { AuthController } from "./auth.controller";

describe("authController", () => {
  let controller: AuthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            login: jest.fn().mockResolvedValue({
              access_token: "token",
              user: { email: "test@example.com" },
            }),
          },
        },
        {
          provide: UsersService,
          useValue: {
            createUser: jest
              .fn()
              .mockResolvedValue({ id: "1", email: "john@doe.com" }),
          },
        },
        {
          provide: SecurityService,
          useValue: {
            checkRateLimit: jest.fn(),
            logFailedAuth: jest.fn(),
            logSuccessfulAuth: jest.fn(),
            getSecurityStats: jest.fn().mockReturnValue({
              totalEvents: 0,
              suspiciousIPs: 0,
              rateLimitedIPs: 0,
              recentEvents: [],
            }),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it("should be defined", () => {
    expect(controller).toBeDefined();
  });

  it("getSecurityStats returns shape", async () => {
    const stats = await controller.getSecurityStats({
      headers: {},
      socket: { remoteAddress: "127.0.0.1" },
    } as any);
    expect(stats).toHaveProperty("totalEvents");
    expect(stats).toHaveProperty("recentEvents");
  });

  it("login uses SecurityService and returns auth result", async () => {
    const result = await controller.login(
      { user: { email: "john@doe.com" } } as any,
      { cookie: jest.fn() } as any,
      {
        headers: { "user-agent": "jest" },
        socket: { remoteAddress: "127.0.0.1" },
      } as any,
    );
    expect(result).toHaveProperty("access_token");
  });

  it("register calls UsersService.createUser and returns user without password", async () => {
    const dto: any = {
      firstName: "John",
      lastName: "Doe",
      email: "john@doe.com",
      password: "Secret123!",
    };
    const res = await controller.register(dto, {
      headers: { "user-agent": "jest" },
      socket: { remoteAddress: "127.0.0.1" },
    } as any);
    expect(res).toHaveProperty("id");
    expect((res as any).password).toBeUndefined();
  });

  it("logout clears cookie and returns message", async () => {
    const clearCookie = jest.fn();
    const res = await controller.logout(
      { clearCookie } as any,
      {
        headers: { "x-forwarded-for": "127.0.0.1" },
        socket: { remoteAddress: "127.0.0.1" },
      } as any,
    );
    expect(clearCookie).toHaveBeenCalled();
    expect(res).toHaveProperty("message");
  });
});
