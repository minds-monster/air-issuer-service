import { Migration } from '@mikro-orm/migrations';

export class Migration20260824150637 extends Migration {

  override up(): void | Promise<void> {
    this.addSql(`create table "tsl_partition" ("id" bigint not null, "bits" int not null default 1, "list" bytea not null, "updated_at" timestamptz not null default now(), primary key ("id"));`);
    this.addSql(`comment on column "tsl_partition"."list" is 'zlib deflated';`);

    this.addSql(`alter table "sd_jwt_vc" add "updated_at" timestamptz not null default now();`);
  }

  override down(): void | Promise<void> {
    this.addSql(`drop table if exists "tsl_partition" cascade;`);

    this.addSql(`alter table "sd_jwt_vc" drop column "updated_at";`);
  }

}
