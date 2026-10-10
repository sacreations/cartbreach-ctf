-- CartBreach CTF — PostgreSQL seed data

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(128),
    email VARCHAR(128),
    role VARCHAR(16) DEFAULT 'guest',
    status VARCHAR(32) DEFAULT 'approved',
    auth_provider VARCHAR(32) DEFAULT 'local',
    google_sub VARCHAR(255) UNIQUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    order_id INTEGER UNIQUE NOT NULL,
    customer_id INTEGER NOT NULL,
    item VARCHAR(256) NOT NULL,
    amount NUMERIC(10,2) NOT NULL,
    status VARCHAR(32) DEFAULT 'pending',
    shipping_notes TEXT
);

CREATE TABLE IF NOT EXISTS system_service_keys (
    id SERIAL PRIMARY KEY,
    key_name VARCHAR(64) NOT NULL,
    -- AES-256-CBC encrypted blob (passphrase: harvest2026, fixed IV: 0000000000000000)
    -- Decrypted value: cb_internal_svc_t0k3n_4dm1n | flag: SLIIT{c4rt_br34ch_f0r3n51c_db_dump}
    encrypted_value TEXT NOT NULL,
    description TEXT
);

-- Users: guest (password: guest123), admin (password: harvest2026)
-- Hashes pre-generated with bcrypt cost 10
INSERT INTO users (username, password_hash, email, role, status, auth_provider) VALUES
    ('guest', '$2b$10$j.wY/4CoTEL7iHu.ktHHmO/zCPz.TQ3c.G43fdzyhmV/Ckg6slQCe', 'guest@cartbreach.local', 'guest', 'approved', 'local'),
    ('admin', '$2b$10$4dtUyWRDSrNNMHhcLGfDmOtRRIFDvmKO9PxBYjTNhsiKaKxN2Q0G2', 'admin@cartbreach.local', 'admin', 'approved', 'local');

-- Orders: order 1001 contains Stage 2 flag in shipping_notes (only admin's order)
INSERT INTO orders (order_id, customer_id, item, amount, status, shipping_notes) VALUES
    (1001, 2, 'Warehouse Dispatch Batch #A1', 9999.00, 'shipped', 'SLIIT{c4rt_br34ch_1d0r_0rd3r_byp455}'),
    (1002, 1, 'Standard Office Supply Kit', 149.99, 'pending', 'Deliver to loading bay 3'),
    (1003, 1, 'Bulk Packaging Materials', 320.50, 'processing', 'Fragile — handle with care'),
    (1004, 1, 'Network Switch x4', 2400.00, 'shipped', 'IT department delivery');

-- Stage 4 forensic artifact: AES-256-CBC encrypted internal service token
-- Plaintext: cb_internal_svc_t0k3n_4dm1n
-- Flag embedded: SLIIT{c4rt_br34ch_f0r3n51c_db_dump}
-- Encrypted with passphrase=harvest2026, IV=00000000000000000000000000000000 (CyberChef-compatible)
INSERT INTO system_service_keys (key_name, encrypted_value, description) VALUES
    ('internal_api_token',
     'U2FsdGVkX19AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH2MRjK9mXpL1vQzNw4fBsYdCkTe8uJaO6rPiFn3lSDHqMGbVUEA=',
     'SLIIT{c4rt_br34ch_f0r3n51c_db_dump} — Internal microservice authentication token (AES-256-CBC, passphrase=cracked admin password)');
