-- Tabla de credenciales
CREATE TABLE credentials (
    id INT PRIMARY KEY,
    user_id INT,
    username VARCHAR(255),
    password VARCHAR(255)
);

-- Tabla de tokens
CREATE TABLE tokens (
    access_token VARCHAR(255) PRIMARY KEY
);

-- Tabla de respuestas de error
CREATE TABLE error_responses (
    message VARCHAR(255) PRIMARY KEY
);

-- Tabla de entradas de contraseñas
CREATE TABLE password_entries (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255)
);

-- Tabla de usuarios
CREATE TABLE users (
    name VARCHAR(255) PRIMARY KEY,
    hash BINARY(64),
    salt BINARY(16),
    token BINARY(64),
    last_active BIGINT
);