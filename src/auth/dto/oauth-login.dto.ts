import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class FacebookOAuthLoginDto {
  @ApiProperty({
    description: "ID Facebook de l'utilisateur",
    example: "123456789012345",
  })
  @IsString()
  @IsNotEmpty()
  id: string;

  @ApiProperty({
    description: "Email de l'utilisateur",
    example: "john.doe@gmail.com",
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: "Nom complet de l'utilisateur",
    example: "John Doe",
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({
    description: "URL de la photo de profil",
    example: "https://graph.facebook.com/123456789012345/picture",
    required: false,
  })
  @IsString()
  @IsOptional()
  picture?: string;
}

export class AppleOAuthLoginDto {
  @ApiProperty({
    description: "ID Apple de l'utilisateur",
    example: "001451.a1b2c3d4e5f6g7h8i9j0.1234",
  })
  @IsString()
  @IsNotEmpty()
  id: string;

  @ApiProperty({
    description: "Email de l'utilisateur",
    example: "john.doe@privaterelay.appleid.com",
    required: false,
  })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiProperty({
    description: "Nom complet de l'utilisateur",
    example: "John Doe",
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string;
}

export class GithubOAuthLoginDto {
  @ApiProperty({
    description: "ID GitHub de l'utilisateur",
    example: "12345678",
  })
  @IsString()
  @IsNotEmpty()
  id: string;

  @ApiProperty({
    description: "Email de l'utilisateur",
    example: "john.doe@gmail.com",
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: "Nom d'utilisateur GitHub",
    example: "johndoe",
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({
    description: "URL de la photo de profil",
    example: "https://avatars.githubusercontent.com/u/12345678",
    required: false,
  })
  @IsString()
  @IsOptional()
  avatar?: string;
}
