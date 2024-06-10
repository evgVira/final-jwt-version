insert into t_user(name, password, email) values ('sam', '$2a$12$PCh6VsuYqMOK5nYhfDcQ2uIP3rlijCtC5SpZCfWumRWv8UT/6p5mO', 'sam@gamil.com'),
                                                 ('max', '$2a$12$PCh6VsuYqMOK5nYhfDcQ2uIP3rlijCtC5SpZCfWumRWv8UT/6p5mO', 'max@gmail.com');

insert into t_role(name) values ('ROLE_USER'),('ROLE_ADMIN');

insert into t_user_role(user_id, role_id) values (1, 1), (2, 2);