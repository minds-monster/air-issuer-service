import {
  ArrayNotEmpty,
  IsArray,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';

/**
 * Mint an SD-JWT-VC and return it to the caller.
 *
 * `scopes` is required and must be non-empty: this credential exists to carry an
 * authorization, and one that asserts nothing is at best useless and at worst a
 * credential someone assumes is working. The vault rejects it anyway, so failing
 * here gives a clearer error than failing there.
 */
export class IssueSdJwtRequestBodyDto {
  @IsString()
  @IsNotEmpty()
  schemaId: string;

  @IsString()
  @IsNotEmpty()
  holderDID: string;

  @IsString()
  @IsNotEmpty()
  mindId: string;

  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  scopes: string[];

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  label?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  audience?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  grantRef?: string;
}
