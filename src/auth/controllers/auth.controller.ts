import { BadRequestException, Body, Controller, Get, HttpCode, HttpStatus, Logger, Post, Req, Request, Res, UseGuards } from "@nestjs/common";
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { Request as ExpressRequest, Response } from "express";

import { UsersService } from "../../users/services/users.service";
import { RegisterDto } from "../dto/register.dto";
import { AuthService } from "../services/auth.service";
import { SecurityService } from "../services/security.service";
import { LocalAuthGuard } from "../strategies/local-auth.guard";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly securityService: SecurityService,
  ) {}

  @ApiOperation({ summary: "Connexion utilisateur" })
  @ApiBody({
    schema: {
      type: "object",
      properties: {
        email: {
          type: "string",
          example: "john.doe@example.com",
        },
        password: {
          type: "string",
          example: "password123",
        },
      },
      required: ["email", "password"],
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Utilisateur connecté avec succès",
    schema: {
      type: "object",
      properties: {
        access_token: {
          type: "string",
          example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        },
        user: {
          type: "object",
          properties: {
            id: { type: "string" },
            email: { type: "string" },
            firstName: { type: "string" },
            lastName: { type: "string" },
            role: { type: "string" },
          },
        },
      },
    },
  })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Identifiants invalides" })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Invalid request" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("login")
  @UseGuards(LocalAuthGuard)
  @HttpCode(HttpStatus.OK)
  async login(@Request() req, @Res({ passthrough: true }) response: Response, @Req() request: ExpressRequest) {
    const ip = this.getClientIP(request);
    const userAgent = request.headers["user-agent"] || "unknown";

    this.logger.log(`🔐 Login attempt from ${ip} for user: ${req.user.email}`);

    try {
      // Apply security checks - rate limiting and suspicious activity detection
      this.securityService.checkRateLimit(ip, userAgent);

      // Validate request parameters for security
      if (!req.user || !req.user.email) {
        this.logger.error(`❌ Invalid user data in request from ${ip}`);
        this.securityService.logFailedAuth(ip, userAgent, "Invalid user data");
        throw new BadRequestException("Invalid authentication data");
      }

      // Generate authentication result
      const authResult = await this.authService.login(req.user);

      // Enhanced secure cookie configuration (same as OAuth)
      const cookieOptions = {
        httpOnly: true, // Prevents client-side JavaScript access
        secure: process.env.NODE_ENV === "production", // HTTPS only in production
        sameSite: (process.env.NODE_ENV === "production" ? "lax" : "strict") as "lax" | "strict", // More flexible in production for cross-origin scenarios
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: "/", // Available site-wide
        domain: process.env.NODE_ENV === "production" ? this.getDomainFromUrl(process.env.FRONTEND_URL || "http://localhost:3000") : undefined,
      };

      this.logger.log(`🍪 Setting secure auth cookie for ${req.user.email} with options:`, {
        httpOnly: cookieOptions.httpOnly,
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        domain: cookieOptions.domain,
      });

      // Set secure authentication cookie
      response.cookie("auth_token", authResult.access_token, cookieOptions);

      // Log successful authentication
      this.logger.log(`✅ Successful login for user: ${req.user.email} from ${ip}`);
      this.securityService.logSuccessfulAuth(ip, userAgent, req.user.email);

      // Return authentication result
      return authResult;
    }
    catch (error) {
      // Log failed authentication attempt
      this.logger.error(`❌ Login failed for user ${req.user?.email || "unknown"} from ${ip}: ${error.message}`);
      this.securityService.logFailedAuth(ip, userAgent, `Login failed: ${error.message}`);
      throw error;
    }
  }

  @ApiOperation({ summary: "Inscription utilisateur" })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Utilisateur créé avec succès",
    schema: {
      type: "object",
      properties: {
        id: { type: "string" },
        firstName: { type: "string" },
        lastName: { type: "string" },
        email: { type: "string" },
        isEmailVerified: { type: "boolean" },
        provider: { type: "string" },
        role: { type: "string" },
      },
    },
  })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: "Données invalides" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("register")
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto, @Req() request: ExpressRequest) {
    const ip = this.getClientIP(request);
    const userAgent = request.headers["user-agent"] || "unknown";

    this.logger.log(`📝 Registration attempt from ${ip} for user: ${registerDto.email}`);

    try {
      // Apply security checks for registration
      this.securityService.checkRateLimit(ip, userAgent);

      // Validate registration data
      if (!registerDto.email || !registerDto.password || !registerDto.firstName || !registerDto.lastName) {
        this.logger.error(`❌ Invalid registration data from ${ip}`);
        this.securityService.logFailedAuth(ip, userAgent, "Invalid registration data");
        throw new BadRequestException("All required fields must be provided");
      }

      // Create user
      const user = await this.usersService.createUser({
        ...registerDto,
      });

      // Remove password from response
      const { password, ...result } = user;

      // Log successful registration
      this.logger.log(`✅ Successful registration for user: ${registerDto.email} from ${ip}`);
      this.securityService.logSuccessfulAuth(ip, userAgent, `Registration: ${registerDto.email}`);

      return result;
    }
    catch (error) {
      // Log failed registration attempt
      this.logger.error(`❌ Registration failed for ${registerDto.email} from ${ip}: ${error.message}`);
      this.securityService.logFailedAuth(ip, userAgent, `Registration failed: ${error.message}`);
      throw error;
    }
  }

  @ApiOperation({ summary: "Déconnexion" })
  @ApiResponse({ status: HttpStatus.OK, description: "Déconnexion réussie" })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: "Unauthorized" })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: "Access denied" })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: "User not found" })
  @Post("logout")
  @HttpCode(HttpStatus.OK)
  async logout(@Res({ passthrough: true }) response: Response, @Req() request: ExpressRequest) {
    const ip = this.getClientIP(request);

    this.logger.log(`🚪 Logout request from ${ip}`);

    try {
      // Enhanced cookie clearing (same as OAuth)
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict" as const,
        path: "/",
        domain: process.env.NODE_ENV === "production" ? this.getDomainFromUrl(process.env.FRONTEND_URL || "http://localhost:3000") : undefined,
      };

      // Clear authentication cookie with same options used to set it
      response.clearCookie("auth_token", cookieOptions);

      this.logger.log(`✅ Logout successful from ${ip}`);
      return { message: "Logout successful" };
    }
    catch (error) {
      this.logger.error(`❌ Logout error from ${ip}: ${error.message}`);
      throw error;
    }
  }

  @ApiOperation({ summary: "Get authentication security statistics" })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Security statistics retrieved successfully",
    schema: {
      type: "object",
      properties: {
        totalEvents: { type: "number" },
        suspiciousIPs: { type: "number" },
        rateLimitedIPs: { type: "number" },
        recentEvents: {
          type: "array",
          items: {
            type: "object",
            properties: {
              ip: { type: "string" },
              userAgent: { type: "string" },
              timestamp: { type: "number" },
              event: { type: "string" },
              details: { type: "string" },
            },
          },
        },
      },
    },
  })
  @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: "Internal server error" })
  @Get("security/stats")
  @HttpCode(HttpStatus.OK)
  async getSecurityStats(@Req() request: ExpressRequest) {
    const ip = this.getClientIP(request);
    this.logger.log(`📊 Security stats request from ${ip}`);

    const stats = this.securityService.getSecurityStats();
    this.logger.log(`📈 Security stats retrieved: ${stats.totalEvents} events, ${stats.suspiciousIPs} suspicious IPs`);

    return stats;
  }

  /**
   * Extract client IP address from request (same logic as OAuth controller)
   */
  private getClientIP(request: ExpressRequest): string {
    const xForwardedFor = request.headers["x-forwarded-for"];
    const xRealIp = request.headers["x-real-ip"];

    if (typeof xForwardedFor === "string") {
      return xForwardedFor.split(",")[0].trim();
    }

    if (typeof xRealIp === "string") {
      return xRealIp.trim();
    }

    return request.socket.remoteAddress || "unknown";
  }

  /**
   * Extract domain from URL for cookie configuration (same logic as OAuth controller)
   */
  private getDomainFromUrl(url: string): string | undefined {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;

      if (process.env.NODE_ENV === "production") {
        const parts = hostname.split(".");
        if (parts.length >= 2) {
          return `.${parts.slice(-2).join(".")}`;
        }
      }

      return hostname;
    }
    catch {
      return undefined;
    }
  }
}
