CREATE DATABASE secure_messaging;

\c secure_messaging

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    nickname VARCHAR(255) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);

-- Messages table
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    encrypted_message TEXT NOT NULL,
    encrypted_aes_key TEXT NOT NULL,
    status VARCHAR(10) NOT NULL,
    expiration TIMESTAMP NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);
