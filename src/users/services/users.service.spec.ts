import { Logger, UnauthorizedException } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import * as argon2 from "argon2";

import { User } from "../../interfaces/user.interface";
import { DbServiceClient } from "./db-service.client";
import { NotificationServiceClient } from "./notification-service.client";
import { UsersService } from "./users.service";

jest.mock("argon2");

describe("usersService", () => {
  let service: UsersService;
  let dbClient: jest.Mocked<DbServiceClient>;
  let _notifClient: jest.Mocked<NotificationServiceClient>;

  const user: User = {
    _id: "u1",
    email: "test@example.com",
    firstName: "Test",
    lastName: "User",
    role: "user" as any,
    password: "$argon2hash",
  } as any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: Logger, useValue: new Logger("UsersServiceTest") },
        {
          provide: DbServiceClient,
          useValue: {
            findUserByEmail: jest.fn(),
            findUserById: jest.fn(),
            getSubscriptionStatus: jest.fn(),
            createUser: jest.fn(),
            updateUserProfile: jest.fn(),
            updateUserPassword: jest.fn(),
            saveOnboardingProgress: jest.fn(),
            completeOnboarding: jest.fn(),
            getOnboardingStatus: jest.fn(),
            createOrUpdateOAuthUser: jest.fn(),
            findUserByOAuth: jest.fn(),
            updateUserSubscriptionInfo: jest.fn(),
            getUserMetrics: jest.fn(),
          },
        },
        {
          provide: NotificationServiceClient,
          useValue: {
            sendWelcomeEmail: jest.fn().mockResolvedValue(true),
          },
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    dbClient = module.get(DbServiceClient) as jest.Mocked<DbServiceClient>;
    _notifClient = module.get(NotificationServiceClient) as jest.Mocked<NotificationServiceClient>;
  });

  describe("findByEmail/Id", () => {
    it("findByEmail returns user", async () => {
      dbClient.findUserByEmail.mockResolvedValue(user);
      await expect(service.findByEmail("test@example.com")).resolves.toEqual(user);
    });

    it("findByIdWithSubscription enriches user", async () => {
      dbClient.findUserById.mockResolvedValue(user);
      dbClient.getSubscriptionStatus.mockResolvedValue({
        hasSubscription: true,
        isActive: true,
        plan: "monthly",
        status: "active",
        trialActive: false,
        daysRemaining: 10,
      } as any);
      const enriched = await service.findByIdWithSubscription("u1");
      expect(enriched?.hasActiveSubscription).toBe(true);
      expect(dbClient.getSubscriptionStatus).toHaveBeenCalledWith("u1");
    });
  });

  describe("validateUserCredentials", () => {
    it("returns null if user not found", async () => {
      dbClient.findUserByEmail.mockResolvedValue(null);
      await expect(service.validateUserCredentials("a", "b")).resolves.toBeNull();
    });

    it("returns user without password if argon2.verify ok", async () => {
      dbClient.findUserByEmail.mockResolvedValue(user);
      (argon2.verify as jest.Mock).mockResolvedValue(true);
      const res = await service.validateUserCredentials("e", "p");
      expect(res).toEqual(expect.objectContaining({ email: user.email }));
    });

    it("returns null if argon2.verify false", async () => {
      dbClient.findUserByEmail.mockResolvedValue(user);
      (argon2.verify as jest.Mock).mockResolvedValue(false);
      await expect(service.validateUserCredentials("e", "p")).resolves.toBeNull();
    });

    it("returns null when argon2 throws", async () => {
      dbClient.findUserByEmail.mockResolvedValue(user);
      (argon2.verify as jest.Mock).mockRejectedValue(new Error("argon2 failed"));
      await expect(service.validateUserCredentials("e", "p")).resolves.toBeNull();
    });
  });

  describe("changePassword", () => {
    it("throws Unauthorized if user missing or no password", async () => {
      dbClient.findUserById.mockResolvedValue(null);
      await expect(service.changePassword("u1", "old", "new")).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it("updates password when verify ok", async () => {
      dbClient.findUserById.mockResolvedValue(user);
      (argon2.verify as jest.Mock).mockResolvedValue(true);
      (argon2.hash as jest.Mock).mockResolvedValue("hashedNew");
      await service.changePassword("u1", "old", "new");
      expect(dbClient.updateUserPassword).toHaveBeenCalledWith("u1", "hashedNew");
    });

    it("throws Unauthorized when verify false", async () => {
      dbClient.findUserById.mockResolvedValue(user);
      (argon2.verify as jest.Mock).mockResolvedValue(false);
      await expect(service.changePassword("u1", "old", "new")).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it("throws Unauthorized when argon2 verify errors", async () => {
      dbClient.findUserById.mockResolvedValue(user);
      (argon2.verify as jest.Mock).mockRejectedValue(new Error("boom"));
      await expect(service.changePassword("u1", "old", "new")).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });

  describe("createUser", () => {
    it("hashes password, delegates to db, and sends welcome email", async () => {
      (argon2.hash as jest.Mock).mockResolvedValue("hashed");
      dbClient.createUser.mockResolvedValue(user);
      const created = await service.createUser({ firstName: "A", lastName: "B", email: user.email, password: "p" });
      expect(dbClient.createUser).toHaveBeenCalledWith(expect.objectContaining({ password: "hashed" }));
      expect(created).toEqual(user);

      // Give a moment for the async welcome email to be triggered
      await new Promise(resolve => setImmediate(resolve));
      expect(_notifClient.sendWelcomeEmail).toHaveBeenCalledWith({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        provider: "email",
        userId: user._id,
      });
    });
  });

  describe("update profile & onboarding", () => {
    it("updateProfile returns null when user not found", async () => {
      dbClient.findUserById.mockResolvedValue(null);
      await expect(service.updateProfile("u1", { firstName: "X" })).resolves.toBeNull();
    });

    it("saveOnboardingProgress throws if user not found", async () => {
      dbClient.findUserById.mockResolvedValue(null);
      await expect(service.saveOnboardingProgress("u1", {})).rejects.toThrow("User not found");
    });
  });
});
