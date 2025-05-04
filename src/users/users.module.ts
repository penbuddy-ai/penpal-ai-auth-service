import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";

import { UsersController } from "./controllers/users.controller";
import { DbServiceClient } from "./services/db-service.client";
import { UsersService } from "./services/users.service";

@Module({
  imports: [
    HttpModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async () => ({
        timeout: 5000,
        maxRedirects: 5,
      }),
    }),
  ],
  controllers: [UsersController],
  providers: [UsersService, DbServiceClient],
  exports: [UsersService],
})
export class UsersModule {}
