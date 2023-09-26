CREATE TABLE tbl_my_policies_configuration (
    config_key varchar(100) NOT NULL,
    config_value TEXT NOT NULL,
    start_date_time DATETIME NOT NULL,
    end_date_time DATETIME NOT NULL,
    is_active BOOLEAN NOT NULL,
    PRIMARY KEY (config_key)
);
