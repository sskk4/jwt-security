CREATE TABLE IF NOT EXISTS user
(
    id            BIGINT                NOT NULL AUTO_INCREMENT PRIMARY KEY,
    firstname     VARCHAR(255)          NOT NULL,
    lastname      VARCHAR(255)          NOT NULL,
    email         VARCHAR(255) UNIQUE   NOT NULL,
    password      VARCHAR(255)          NOT NULL,
    role          ENUM ('ADMIN', 'USER') NOT NULL
    );

CREATE TABLE IF NOT EXISTS refresh_token
(
    id      BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    token   BINARY(16),
    created DATETIME,
    expired DATETIME,
    user_id BIGINT UNIQUE,
    FOREIGN KEY (user_id) REFERENCES user (id)
    );

CREATE TABLE IF NOT EXISTS user_seq
(
    next_val BIGINT
);

INSERT INTO user_seq VALUES (0);