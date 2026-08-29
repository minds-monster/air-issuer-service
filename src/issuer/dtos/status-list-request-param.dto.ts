import { IsNotEmpty, IsNumber, Min } from 'class-validator';

export class StatusListRequestParamDto {
  @IsNumber()
  @IsNotEmpty()
  @Min(0)
  partition: number;
}
