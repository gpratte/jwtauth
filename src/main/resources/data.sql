drop table if exists user;

create table user (id bigint not null auto_increment, username varchar(255), password varchar(255), primary key (id));

-- password is password1
INSERT INTO user (id, username, password) VALUES (1, 'admin1', '$2a$04$Ye7/lJoJin6.m9sOJZ9ujeTgHEVM4VXgI2Ingpsnf9gXyXEXf/IlW');
