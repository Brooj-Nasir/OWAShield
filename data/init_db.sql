-- ______________________________________________________
-- SQL Injection
-- ______________________________________________________
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO users (username, password) VALUES
('brooj', 'broojpass'),
('admin', 'supersecret'),
('alice', 'password123'),
('bob', 'securepass');

-- ______________________________________________________
-- broken_authentication
-- ______________________________________________________
-- Add new table and update users
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
CREATE TABLE sensitive_data (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    secret_note TEXT
);

-- Update existing users
UPDATE users SET role = 'admin' WHERE username = 'admin';

-- Insert sensitive data
INSERT INTO sensitive_data (user_id, secret_note) VALUES
(1, 'Admin secret: 8f7d2e9c1b'),
(2, 'Alice secret: 5a3b9c8d2e'),
(3, 'Bob secret: 9e2c8a5b3d');


-- ______________________________________________________
-- sensitive_data_exposure
-- ______________________________________________________
CREATE TABLE payment_info (
    id INTEGER PRIMARY KEY,
    card_number TEXT,
    encrypted_card TEXT
);


-- ______________________________________________________
-- Broken authentication
-- ______________________________________________________
ALTER TABLE users ADD COLUMN password_hash TEXT;
UPDATE users SET password_hash = 
    CASE 
        WHEN username = 'admin' THEN '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW'  -- bcrypt hash of 'secret'
        ELSE '$2b$12$W7dCTwZ6Jb4.1Uqz7H3dHeqACQOQY1N9x9Uoq5D3pVpB5Rkz4X1Ku'  -- bcrypt hash of 'password'
    END;