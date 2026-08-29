import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { cacheLoader } from '@mocanetwork/identity-js-sdk';
import { HttpService } from '@nestjs/axios';
import { JsonLd } from 'jsonld/jsonld-spec';

export const createDocumentLoader = (httpService: HttpService): DocumentLoader => {
  const documentLoader: DocumentLoader = async (url: string) => {
    const response = await httpService.axiosRef.get<JsonLd>(url);

    return {
      contextUrl: undefined,
      documentUrl: url,
      document: response.data,
    };
  };

  return cacheLoader({ documentLoader });
};
