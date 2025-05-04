import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class GoogleOAuthLoginDto {
  @ApiProperty({
    description: "ID Google de l'utilisateur",
    example: "123456789012345678901",
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
    description: "Prénom de l'utilisateur",
    example: "John",
    required: false,
  })
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiProperty({
    description: "Nom de famille de l'utilisateur",
    example: "Doe",
    required: false,
  })
  @IsString()
  @IsOptional()
  lastName?: string;

  @ApiProperty({
    description: "Nom complet de l'utilisateur",
    example: "John Doe",
    required: false,
  })
  @IsString()
  @IsOptional()
  displayName?: string;

  @ApiProperty({
    description: "URL de la photo de profil",
    example: "https://lh3.googleusercontent.com/a/photo.jpg",
    required: false,
  })
  @IsString()
  @IsOptional()
  picture?: string;
}

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
