create table if not exists t_user
(
    id serial primary key not null unique,
    name varchar(100) not null,
    password varchar(100) not null,
    email varchar(100) not null
);

create table if not exists t_role
(
    id serial primary key not null,
    name varchar(100) not null
);

create table if not exists t_user_role
(
    user_id int not null,
    role_id int not null,
    foreign key (user_id) references t_user(id),
    foreign key (role_id) references t_role(id)
);

create table t_deactivated_token
(
    id uuid primary key,
    c_keep_until timestamp not null check ( c_keep_until > now() )
);