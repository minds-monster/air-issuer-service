import { IsNotEmpty, IsString, MaxLength } from 'class-validator';

export class JsonWebKeyDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(60)
  x: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(60)
  y: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(60)
  crv: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(60)
  kty: string;
}
