drop table if exists user;

create table user (id bigint not null auto_increment, username varchar(255), password varchar(255), primary key (id));

-- password is password
INSERT INTO user (id, username, password) VALUES (1, 'admin', '$2a$10$qXQo4z4oXKPEKyYO7bAQmOQ9PhIcHK4LOo/L1U9j/xkLEmseLWECK');
