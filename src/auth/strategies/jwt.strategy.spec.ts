import { UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Test, TestingModule } from "@nestjs/testing";
import { Strategy } from "passport-jwt";

import { AuthService } from "../services/auth.service";
import { JwtStrategy } from "./jwt.strategy";

describe("jwtStrategy", () => {
  let strategy: JwtStrategy;
  let authService: jest.Mocked<AuthService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        { provide: AuthService, useValue: { validateUserById: jest.fn() } },
        { provide: ConfigService, useValue: { get: () => "test_secret" } },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
    authService = module.get(AuthService) as jest.Mocked<AuthService>;
  });

  it("extends passport-jwt Strategy", () => {
    expect(strategy).toBeInstanceOf(Strategy);
  });

  it("validates payload via AuthService", async () => {
    authService.validateUserById.mockResolvedValue({ _id: "u1", email: "e@x.com" } as any);
    const user = await strategy.validate({ sub: "u1", email: "e@x.com", roles: ["user"] } as any);
    expect(user).toEqual({ id: "u1", email: "e@x.com", roles: ["user"] });
    expect(authService.validateUserById).toHaveBeenCalledWith("u1");
  });

  it("throws Unauthorized when user not found", async () => {
    authService.validateUserById.mockResolvedValue(null);
    await expect(strategy.validate({ sub: "u2" } as any)).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
