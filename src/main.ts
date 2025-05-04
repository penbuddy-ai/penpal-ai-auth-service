import { Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import * as cookieParser from "cookie-parser";

import { AppModule } from "./app.module";

async function bootstrap() {
  const logger = new Logger("Auth Service");
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Utiliser cookie-parser pour traiter les cookies
  app.use(cookieParser());

  // Set global prefix for all routes
  app.setGlobalPrefix("api/v1");

  // Enable validation pipes
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));

  // Configure CORS
  const corsOrigins = configService.get<string>("CORS_ALLOWED_ORIGINS")?.split(",") || [];
  app.enableCors({
    origin: corsOrigins,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    credentials: true,
  });

  // Configure Swagger
  const swaggerConfig = new DocumentBuilder()
    .setTitle("Penpal AI - Auth Service")
    .setDescription("API Documentation for Penpal AI Authentication Service")
    .setVersion("1.0")
    .addTag("auth", "Authentication endpoints")
    .addTag("users", "User management endpoints")
    .addBearerAuth(
      {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
        name: "Authorization",
        description: "Enter JWT token",
        in: "header",
      },
      "JWT-auth",
    )
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup("api/v1/docs", app, document);

  const port = configService.get<number>("PORT") || 3000;
  await app.listen(port);
  logger.log(`Application is running on: http://localhost:${port}/api/v1`);
  logger.log(`Swagger documentation is available at: http://localhost:${port}/api/v1/docs`);
}
bootstrap();
