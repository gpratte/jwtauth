drop table if exists user_roles;
drop table if exists role;
drop table if exists user;

create table user (id bigint not null auto_increment, username varchar(255), password varchar(255), primary key (id));

-- password is password
INSERT INTO user (id, username, password) VALUES (1, 'admin', '$2a$10$qXQo4z4oXKPEKyYO7bAQmOQ9PhIcHK4LOo/L1U9j/xkLEmseLWECK');

-- password is password
INSERT INTO user (id, username, password) VALUES (2, 'Bob', '$2a$10$qXQo4z4oXKPEKyYO7bAQmOQ9PhIcHK4LOo/L1U9j/xkLEmseLWECK');

create table role (id bigint auto_increment, description varchar(255), name varchar(255), primary key (id));

INSERT INTO role (id, description, name) VALUES (1, 'Admin role', 'ADMIN');
INSERT INTO role (id, description, name) VALUES (2, 'User role', 'USER');

create table user_roles (user_id bigint not null, role_id bigint not null, primary key (user_id, role_id));

alter table user_roles add constraint fk_role_id foreign key (role_id) references role (id);

alter table user_roles add constraint fk_user_id foreign key (user_id) references user (id);

INSERT INTO user_roles (user_id, role_id) VALUES (1, 1);
INSERT INTO user_roles (user_id, role_id) VALUES (2, 2);
