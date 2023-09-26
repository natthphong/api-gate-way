TRUNCATE TABLE tbl_my_policies_configuration;
ALTER TABLE tbl_my_policies_configuration ADD version varchar(10) NOT NULL;
ALTER TABLE tbl_my_policies_configuration DROP PRIMARY KEY, ADD PRIMARY KEY(config_key,version);