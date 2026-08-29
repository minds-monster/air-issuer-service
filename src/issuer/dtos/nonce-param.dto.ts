import { IsNotEmpty, IsNumberString, MaxLength } from 'class-validator';

export class NonceParamDto {
  @IsNumberString()
  @IsNotEmpty()
  @MaxLength(20)
  nonce: string;
}
