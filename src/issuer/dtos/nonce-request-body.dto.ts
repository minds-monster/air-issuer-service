import { IsEnum, IsNotEmpty, IsNumberString, IsOptional, MaxLength } from 'class-validator';
import { ProofType } from '../enums/proof-type.enum';

export class NonceRequestBodyDto {
  @IsNumberString()
  @IsNotEmpty()
  @MaxLength(20)
  nonce: string;

  @IsEnum(ProofType)
  @IsOptional()
  proofType?: ProofType;
}
