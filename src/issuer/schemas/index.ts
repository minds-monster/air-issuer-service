import { BaseSchema } from './base-schema';

import Schema1 from './schema-01KKX3Q7DEK0GM2TCKMMHA';
import SchemaXDataAccess from './schema-01KZ91Q7HRK18J1M08S1KP';

// Singletons: IssuerService indexes these by schemaId at construction, and the
// XDataAccess schema carries per-issuance claims on the instance (see its `pending`
// field), so the runner must mutate the same object the service resolved.
const schemas: BaseSchema[] = [new Schema1(), new SchemaXDataAccess()];

export default schemas;
