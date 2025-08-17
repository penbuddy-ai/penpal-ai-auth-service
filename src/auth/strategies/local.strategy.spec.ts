import { UnauthorizedException } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import { Strategy } from "passport-local";

import { AuthService } from "../services/auth.service";
import { LocalStrategy } from "./local.strategy";

describe("localStrategy", () => {
  let strategy: LocalStrategy;
  let authService: jest.Mocked<AuthService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LocalStrategy,
        {
          provide: AuthService,
          useValue: {
            validateUser: jest.fn(),
          },
        },
      ],
    }).compile();

    strategy = module.get<LocalStrategy>(LocalStrategy);
    authService = module.get(AuthService) as jest.Mocked<AuthService>;
  });

  it("extends passport-local Strategy", () => {
    expect(strategy).toBeInstanceOf(Strategy);
  });

  it("validates user via AuthService", async () => {
    authService.validateUser.mockResolvedValue({ _id: "u1", email: "e@x.com" } as any);
    const res = await strategy.validate("e@x.com", "pwd");
    expect(res).toEqual({ _id: "u1", email: "e@x.com" });
    expect(authService.validateUser).toHaveBeenCalledWith("e@x.com", "pwd");
  });

  it("throws Unauthorized if validateUser returns null", async () => {
    authService.validateUser.mockResolvedValue(null);
    await expect(strategy.validate("e", "p")).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
