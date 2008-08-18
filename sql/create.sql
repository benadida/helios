--
-- the PostgreSQL data model for running Helios on its own, non-Google-App-Engine stack.
--



create sequence election_id_seq;

create table users (
	user_id		integer not null primary key,
	name		varchar(200) not null,
	email		varchar(200) not null unique,
	verified_p	boolean default 'f' not null,
	verification_code	varchar(20),
	password_salt	varchar(40) not null,
	password_hash	varchar(40) not null
);

create table elections (
  election_id           integer not null primary key,
  admin_user_id		      integer not null references users(user_id),
  election_type         varchar(100) not null default 'homomorphic',
  name			            varchar(200),
  -- the hash of the election, once set, should not be unset
  election_hash         varchar(40) unique,
  questions_json        text,
  public_key_json	      text,
  private_key_json	    text,
  election_frozen_at	  timestamp,
  voting_starts_at      timestamp not null,
  voting_ends_at        timestamp not null,
  -- open registration
  openreg_enabled       boolean not null default 'f',
  encrypted_tally       text,
  running_tally         text,
  decryption_proof      text,
  result_json           text
);

create sequence voter_id_seq;
  
create table voters (
  voter_id              integer not null primary key,
  election_id           integer not null references elections(election_id),
  email                 varchar(200),
  openid_url            varchar(400),
  constraint email_or_openid_nn check (email is not null or openid_url is not null),
  constraint voters_email_un unique (election_id, email),
  constraint voters_openid_un unique (election_id, openid_url),
  name                  varchar(200) not null,
  password              varchar(20),
  -- keeping track of casting and content
  cast_id               varchar(200),
  tallied_at            timestamp,
  vote                  text,
  vote_hash             varchar(40)
);