import { Module } from "@nestjs/common";

import { HttpLoggingInterceptor } from "./interceptors/http-logging.interceptor";

@Module({
  providers: [HttpLoggingInterceptor],
  exports: [HttpLoggingInterceptor],
})
export class CommonModule {}
