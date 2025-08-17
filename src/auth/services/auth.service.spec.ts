import { Logger } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Test, TestingModule } from "@nestjs/testing";

import { User } from "../../interfaces/user.interface";
import { UsersService } from "../../users/services/users.service";
import { AuthService } from "./auth.service";

describe("authService", () => {
  let service: AuthService;
  let usersService: jest.Mocked<UsersService>;
  let jwtService: jest.Mocked<JwtService>;

  const mockUser = {
    _id: "u1",
    email: "test@example.com",
    firstName: "Test",
    lastName: "User",
    role: "user",
  } as unknown as Omit<User, "password">;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: Logger, useValue: new Logger("AuthServiceTest") },
        {
          provide: UsersService,
          useValue: {
            validateUserCredentials: jest.fn(),
            findById: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue("signed.jwt.token"),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService) as jest.Mocked<UsersService>;
    jwtService = module.get(JwtService) as jest.Mocked<JwtService>;
  });

  describe("validateUser", () => {
    it("returns user on valid credentials", async () => {
      usersService.validateUserCredentials.mockResolvedValue(mockUser);
      await expect(service.validateUser("test@example.com", "secret")).resolves.toEqual(mockUser);
      expect(usersService.validateUserCredentials).toHaveBeenCalledWith("test@example.com", "secret");
    });

    it("returns null when credentials invalid", async () => {
      usersService.validateUserCredentials.mockResolvedValue(null);
      await expect(service.validateUser("a@b.c", "bad")).resolves.toBeNull();
    });

    it("propagates error from usersService", async () => {
      usersService.validateUserCredentials.mockRejectedValue(new Error("db down"));
      await expect(service.validateUser("a@b.c", "x")).rejects.toThrow("db down");
    });
  });

  describe("login", () => {
    it("signs jwt and returns token + public user", async () => {
      const result = await service.login(mockUser);
      expect(jwtService.sign).toHaveBeenCalledWith({ sub: "u1", email: mockUser.email, roles: [mockUser.role] });
      expect(result).toEqual({
        access_token: "signed.jwt.token",
        user: {
          id: "u1",
          email: mockUser.email,
          firstName: mockUser.firstName,
          lastName: mockUser.lastName,
          role: mockUser.role,
        },
      });
    });
  });

  describe("validateUserById", () => {
    it("returns user when found", async () => {
      (usersService.findById as jest.Mock).mockResolvedValue(mockUser);
      await expect(service.validateUserById("u1")).resolves.toEqual(mockUser);
    });

    it("returns null when not found", async () => {
      (usersService.findById as jest.Mock).mockResolvedValue(null);
      await expect(service.validateUserById("u2")).resolves.toBeNull();
    });

    it("propagates error from usersService", async () => {
      (usersService.findById as jest.Mock).mockRejectedValue(new Error("boom"));
      await expect(service.validateUserById("u3")).rejects.toThrow("boom");
    });
  });
});
