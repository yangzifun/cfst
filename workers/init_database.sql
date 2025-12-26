-- ========================================================
-- Cloudflare Worker 配置管理器 - 数据库简化脚本
-- 版本: v3.0.2 (仅保留实际使用的表)
-- ========================================================

-- ========================================================
-- 1. 配置表 
-- ========================================================
CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    config_data TEXT NOT NULL,
    protocol TEXT NOT NULL,
    remark TEXT,
    domain_hosting TEXT NOT NULL DEFAULT 'Cloudflare',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s')),
    UNIQUE(uuid, config_data)
);

-- 配置表索引 (如果不存在则创建)
CREATE INDEX IF NOT EXISTS idx_configs_uuid ON configs(uuid);
CREATE INDEX IF NOT EXISTS idx_configs_protocol ON configs(protocol);
CREATE INDEX IF NOT EXISTS idx_configs_domain_hosting ON configs(domain_hosting);
CREATE INDEX IF NOT EXISTS idx_configs_uuid_config ON configs(uuid, config_data);

-- ========================================================
-- 2. 访问日志表 
-- ========================================================
CREATE TABLE IF NOT EXISTS config_access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,                   -- 访问的配置UUID
    query_type TEXT NOT NULL,             -- 记录类型: 'subscription' 或 'api-generation'
    client_ip TEXT,                       -- 客户端IP地址
    user_agent TEXT,                      -- 用户代理字符串
    created_at TEXT DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 访问日志表索引
CREATE INDEX IF NOT EXISTS idx_access_logs_uuid ON config_access_logs(uuid);
CREATE INDEX IF NOT EXISTS idx_access_logs_date ON config_access_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_access_logs_type ON config_access_logs(query_type);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON config_access_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_uuid_date ON config_access_logs(uuid, created_at);

-- ========================================================
-- 3. IP池表
-- ========================================================
CREATE TABLE IF NOT EXISTS cfips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,                     -- IP地址 (IPv4/IPv6)
    ip_type TEXT NOT NULL,                -- IP类型 (v4/v6)
    carrier TEXT NOT NULL,                -- 运营商 (CT=电信, CU=联通, CM=移动, ALL等)
    source TEXT DEFAULT 'unknown',        -- IP来源 (hostmonit_v4/hostmonit_v6/vps789等)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    UNIQUE(ip, carrier)                   -- 复合唯一约束，保证同一个IP和运营商组合只有一个
);

-- IP池表索引
CREATE INDEX IF NOT EXISTS idx_cfips_type ON cfips(ip_type);
CREATE INDEX IF NOT EXISTS idx_cfips_carrier ON cfips(carrier);
CREATE INDEX IF NOT EXISTS idx_cfips_source ON cfips(source);

-- ========================================================
-- 4. 优选域名表
-- ========================================================
CREATE TABLE IF NOT EXISTS cf_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,          -- 优选域名
    remark TEXT,                          -- 备注说明
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    updated_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- 优选域名表索引
CREATE INDEX IF NOT EXISTS idx_cf_domains_domain ON cf_domains(domain);

-- ========================================================
-- 5. 自动更新设置表
-- ========================================================
CREATE TABLE IF NOT EXISTS auto_update_settings (
    source TEXT PRIMARY KEY,              -- 来源标识
    enabled INTEGER NOT NULL DEFAULT 1,   -- 是否启用 (0=禁用, 1=启用)
    updated_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- ========================================================
-- 6. 管理用户表
-- ========================================================
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    mfa_enabled INTEGER DEFAULT 0,        -- MFA是否启用 (0=禁用, 1=启用)
    mfa_secret TEXT,                      -- MFA密钥 (TOTP secret)
    last_mfa_login INTEGER DEFAULT 0,     -- 上次MFA登录时间戳 (毫秒)
    last_backup_login INTEGER DEFAULT 0,  -- 上次备份码登录时间戳 (毫秒)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- 管理用户表索引
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);

-- ========================================================
-- 7. MFA备份码表
-- ========================================================
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,               -- 关联的用户名
    code TEXT NOT NULL,                   -- 备份码 (哈希值)
    used INTEGER DEFAULT 0,               -- 是否已使用 (0=未使用, 1=已使用)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    used_at INTEGER DEFAULT 0             -- 使用时间戳 (毫秒)
);

-- MFA备份码表索引
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(username);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_used ON mfa_backup_codes(used);

-- ========================================================
-- 8. 初始化数据
-- ========================================================

-- 初始化默认管理员账户 (如果不存在)
INSERT OR IGNORE INTO admin_users (username, password_hash, mfa_enabled) VALUES 
('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 0);

-- 初始化自动更新配置 (如果不存在)
INSERT OR IGNORE INTO auto_update_settings (source, enabled) VALUES 
('global_enabled', 1),           -- 全局开关
('hostmonit_v4', 1),             -- HostMonit IPv4
('hostmonit_v6', 0),             -- HostMonit IPv6 (默认禁用)
('vps789', 1),                   -- Vps789
('last_executed', 0);            -- 上次执行时间戳占位符

-- ========================================================
-- 9. API密钥表 (用于IP更新API的鉴权)
-- ========================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_name TEXT NOT NULL,               -- API密钥名称
    api_key TEXT UNIQUE NOT NULL,         -- API密钥 (唯一)
    secret_key TEXT,                      -- 密钥 (可选，用于更复杂的鉴权)
    enabled INTEGER NOT NULL DEFAULT 1,   -- 是否启用 (0=禁用, 1=启用)
    permissions TEXT DEFAULT 'ip_update', -- 权限列表，逗号分隔
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    updated_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    last_used_at INTEGER DEFAULT 0,       -- 最后使用时间戳
    usage_count INTEGER DEFAULT 0         -- 使用次数统计
);

-- API密钥表索引
CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);
CREATE INDEX IF NOT EXISTS idx_api_keys_created ON api_keys(created_at);

-- 初始化一个默认的API密钥 (如果需要)
INSERT OR IGNORE INTO api_keys (key_name, api_key, secret_key, enabled, permissions) VALUES 
('default_ip_update_key', 'default_key_12345', NULL, 1, 'ip_update');

-- ========================================================
-- 10. 简单查询验证
-- ========================================================

-- 显示创建的表数量
SELECT '数据库表创建完成!' as message;
SELECT COUNT(*) as total_tables FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';
