import { IsEnum, IsOptional } from 'class-validator';
import { ProofType } from '../enums/proof-type.enum';

export class RevocationStatusRequestQueryDto {
  @IsEnum(ProofType)
  @IsOptional()
  proofType?: ProofType;
}
