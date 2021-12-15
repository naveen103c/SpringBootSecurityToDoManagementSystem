INSERT into users(username,password,email,enabled) values ('user','{noop}userPass','user@gmail.com',true);
INSERT into users(username,password,email,enabled) values ('admin','{noop}adminPass','admin@gmail.com',true);

INSERT into authorities values ('user','USER');
INSERT into authorities values ('admin','ADMIN');