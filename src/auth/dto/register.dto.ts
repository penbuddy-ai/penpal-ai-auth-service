import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class RegisterDto {
  @ApiProperty({
    description: "Le prénom de l'utilisateur",
    example: "John",
  })
  @IsNotEmpty()
  @IsString()
  firstName: string;

  @ApiProperty({
    description: "Le nom de famille de l'utilisateur",
    example: "Doe",
  })
  @IsNotEmpty()
  @IsString()
  lastName: string;

  @ApiProperty({
    description: "L'adresse email de l'utilisateur",
    example: "john.doe@example.com",
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({
    description: "Le mot de passe de l'utilisateur (minimum 8 caractères)",
    example: "password123",
    minLength: 8,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  password: string;
}
