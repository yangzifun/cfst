-- ========================================================
-- Cloudflare Worker 配置管理器 - 数据库完整初始化脚本
-- 版本: v3.0.0 (增加用户系统)
-- ========================================================

-- ========================================================
-- 0. 用户表 (新增 - 核心功能)
-- ========================================================
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,          -- 登录用户名
    email TEXT,                             -- 邮箱（可选，可用于找回密码等）
    password_hash TEXT NOT NULL,            -- bcrypt 或 SHA-256 加密后的密码
    created_at INTEGER NOT NULL DEFAULT (strftime('%s')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s'))
);

-- 用户表索引
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ========================================================
-- 1. 配置表 (存储代理配置 - 已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,                    -- ✅ 允许 NULL，升级后与users表关联
    uuid TEXT NOT NULL,
    config_data TEXT NOT NULL,
    protocol TEXT NOT NULL,
    remark TEXT,
    domain_hosting TEXT NOT NULL DEFAULT 'Cloudflare',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,  -- 新增外键约束
    UNIQUE(user_id, uuid, config_data)
);

-- 配置表索引 (如果不存在则创建)
CREATE INDEX IF NOT EXISTS idx_configs_uuid ON configs(uuid);
CREATE INDEX IF NOT EXISTS idx_configs_protocol ON configs(protocol);
CREATE INDEX IF NOT EXISTS idx_configs_domain_hosting ON configs(domain_hosting);
CREATE INDEX IF NOT EXISTS idx_configs_uuid_config ON configs(uuid, config_data);
CREATE INDEX IF NOT EXISTS idx_configs_user_id ON configs(user_id);  -- 新增索引

-- ========================================================
-- 2. 访问日志表 (记录配置访问统计 - 已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS config_access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,                   -- 访问的配置UUID
    query_type TEXT NOT NULL,             -- 记录类型: 'subscription' 或 'api-generation'
    client_ip TEXT,                       -- 客户端IP地址
    user_agent TEXT,                      -- 用户代理字符串
    referer TEXT,                         -- 来源页面 (可选)
    country TEXT,                         -- 国家/地区 (可选)
    region TEXT,                          -- 区域 (可选)
    city TEXT,                            -- 城市 (可选)
    created_at TEXT DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 访问日志表索引
CREATE INDEX IF NOT EXISTS idx_access_logs_uuid ON config_access_logs(uuid);
CREATE INDEX IF NOT EXISTS idx_access_logs_date ON config_access_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_access_logs_type ON config_access_logs(query_type);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON config_access_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_uuid_date ON config_access_logs(uuid, created_at);

-- ========================================================
-- 3. 用户管理表 (管理员账户 - 已有表，保留)
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

-- 管理员用户表索引
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);

-- ========================================================
-- 4. IP池表 (存储优选IP地址 - 已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS cfips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,                     -- IP地址 (IPv4/IPv6)
    ip_type TEXT NOT NULL,                -- IP类型 (v4/v6)
    carrier TEXT NOT NULL,                -- 运营商 (CT=电信, CU=联通, CM=移动, ALL等)
    source TEXT DEFAULT 'unknown',        -- IP来源 (hostmonit_v4/hostmonit_v6/vps789等)
    latency INTEGER DEFAULT 0,            -- 延迟 (毫秒，可选)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    UNIQUE(ip, carrier)                   -- 复合唯一约束，保证同一个IP和运营商组合只有一个
);

-- IP池表索引
CREATE INDEX IF NOT EXISTS idx_cfips_type ON cfips(ip_type);
CREATE INDEX IF NOT EXISTS idx_cfips_carrier ON cfips(carrier);
CREATE INDEX IF NOT EXISTS idx_cfips_source ON cfips(source);
CREATE INDEX IF NOT EXISTS idx_cfips_latency ON cfips(latency);

-- ========================================================
-- 5. 优选域名表 (已有表，保留)
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
-- 6. 自动更新设置表 (已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS auto_update_settings (
    source TEXT PRIMARY KEY,              -- 来源标识
    enabled INTEGER NOT NULL DEFAULT 1,   -- 是否启用 (0=禁用, 1=启用)
    update_interval INTEGER DEFAULT 3600, -- 更新间隔 (秒，默认1小时)
    updated_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- ========================================================
-- 7. MFA备份码表 (已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,               -- 关联的用户名
    code TEXT NOT NULL,                   -- 备份码 (哈希值)
    used INTEGER DEFAULT 0,               -- 是否已使用 (0=未使用, 1=已使用)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    used_at INTEGER DEFAULT 0,            -- 使用时间戳 (毫秒),
    FOREIGN KEY (username) REFERENCES admin_users(username) ON DELETE CASCADE
);

-- MFA备份码表索引
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(username);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_used ON mfa_backup_codes(used);

-- ========================================================
-- 8. 系统日志表 (已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,                        -- 操作用户名
    action TEXT NOT NULL,                 -- 操作类型 (login/add_config/update_ip等)
    details TEXT,                         -- 操作详情 (JSON格式)
    ip_address TEXT,                      -- 操作IP地址
    user_agent TEXT,                      -- 用户代理
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- 系统日志表索引
CREATE INDEX IF NOT EXISTS idx_system_logs_username ON system_logs(username);
CREATE INDEX IF NOT EXISTS idx_system_logs_action ON system_logs(action);
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs(created_at);

-- ========================================================
-- 9. API访问统计表 (已有表，保留)
-- ========================================================
CREATE TABLE IF NOT EXISTS api_access_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,               -- API端点路径
    method TEXT NOT NULL,                 -- HTTP方法
    count INTEGER DEFAULT 1,              -- 访问次数
    last_access INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- API访问统计表索引
CREATE INDEX IF NOT EXISTS idx_api_access_stats_endpoint ON api_access_stats(endpoint);
CREATE INDEX IF NOT EXISTS idx_api_access_stats_method ON api_access_stats(method);

-- ========================================================
-- 10. 初始化数据和升级语句
-- ========================================================

-- 初始化默认管理员账户 (如果不存在)
INSERT OR IGNORE INTO admin_users (username, password_hash, mfa_enabled) VALUES 
('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 0);

-- 初始化自动更新配置 (如果不存在)
INSERT OR IGNORE INTO auto_update_settings (source, enabled, update_interval) VALUES 
('global_enabled', 1, 3600),           -- 全局开关
('hostmonit_v4', 1, 7200),             -- HostMonit IPv4 (默认2小时更新)
('hostmonit_v6', 0, 7200),             -- HostMonit IPv6 (默认禁用)
('vps789', 1, 10800),                  -- Vps789 (默认3小时更新)
('last_executed', 0, 0);               -- 上次执行时间戳

-- ========================================================
-- 11. 数据库升级检查与兼容性处理
-- ========================================================

-- 检查configs表是否需要新增user_id外键索引 (如果是从旧版升级)
-- 注意: 您原来的configs表创建语句中已包含user_id字段，这里确保索引存在
-- 如果您的旧数据库中没有这个字段，需要先执行以下ALTER TABLE语句:
-- ALTER TABLE configs ADD COLUMN user_id INTEGER;

-- 检查configs表的外键约束是否已建立
-- 如果您的旧configs表中没有外键约束，可以添加:
-- CREATE TRIGGER IF NOT EXISTS fk_configs_user_id
-- BEFORE DELETE ON users
-- FOR EACH ROW
-- BEGIN
--    UPDATE configs SET user_id = NULL WHERE user_id = OLD.id;
-- END;

-- ========================================================
-- 12. 视图定义 (可选，根据需求创建)
-- ========================================================

-- 创建每日访问统计视图
CREATE VIEW IF NOT EXISTS daily_access_stats AS
SELECT 
    DATE(created_at) as date,
    COUNT(*) as total_requests,
    COUNT(DISTINCT uuid) as unique_uuids,
    COUNT(DISTINCT client_ip) as unique_ips,
    SUM(CASE WHEN query_type = 'subscription' THEN 1 ELSE 0 END) as subscription_requests,
    SUM(CASE WHEN query_type = 'api-generation' THEN 1 ELSE 0 END) as apigen_requests
FROM config_access_logs
GROUP BY DATE(created_at);

-- 创建用户配置统计视图 (新增)
CREATE VIEW IF NOT EXISTS user_config_stats AS
SELECT 
    u.username,
    u.id as user_id,
    COUNT(DISTINCT c.uuid) as owned_uuid_count,
    COUNT(c.id) as config_count,
    GROUP_CONCAT(DISTINCT c.protocol) as protocols,
    GROUP_CONCAT(DISTINCT c.domain_hosting) as hostings
FROM users u
LEFT JOIN configs c ON u.id = c.user_id
GROUP BY u.id;

-- 创建热门配置视图
CREATE VIEW IF NOT EXISTS popular_configs AS
SELECT 
    c.uuid,
    c.protocol,
    c.domain_hosting,
    u.username as owner_name,
    COUNT(*) as access_count,
    SUM(CASE WHEN cal.query_type = 'subscription' THEN 1 ELSE 0 END) as subscription_count,
    SUM(CASE WHEN cal.query_type = 'api-generation' THEN 1 ELSE 0 END) as apigen_count,
    MIN(cal.created_at) as first_access,
    MAX(cal.created_at) as last_access,
    COUNT(DISTINCT cal.client_ip) as unique_clients
FROM configs c
LEFT JOIN config_access_logs cal ON c.uuid = cal.uuid
LEFT JOIN users u ON c.user_id = u.id
GROUP BY c.uuid
ORDER BY access_count DESC;

-- 创建域名托管统计视图
CREATE VIEW IF NOT EXISTS hosting_stats AS
SELECT 
    domain_hosting,
    COUNT(*) as config_count,
    COUNT(DISTINCT uuid) as uuid_count,
    GROUP_CONCAT(DISTINCT protocol) as protocols,
    COUNT(DISTINCT user_id) as user_count,
    MIN(created_at) as first_created,
    MAX(created_at) as last_created
FROM configs
GROUP BY domain_hosting
ORDER BY config_count DESC;

-- ========================================================
-- 13. 查询系统信息
-- ========================================================

-- 显示所有表信息
SELECT '数据库表创建/更新完成!' as message;

-- 显示表结构概览
SELECT 
    name as table_name, 
    CASE 
        WHEN sql LIKE '%CREATE TABLE%' THEN 'Table' 
        WHEN sql LIKE '%CREATE VIEW%' THEN 'View' 
        ELSE 'Other' 
    END as type,
    sql
FROM sqlite_master 
WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
ORDER BY 
    CASE 
        WHEN name = 'users' THEN 1
        WHEN name = 'configs' THEN 2
        WHEN name = 'config_access_logs' THEN 3
        WHEN name = 'admin_users' THEN 4
        ELSE 5
    END;

-- 显示初始化数据统计
SELECT 'users 记录数:' as table_name, COUNT(*) as record_count FROM users
UNION ALL
SELECT 'configs 记录数:', COUNT(*) FROM configs
UNION ALL
SELECT 'config_access_logs 记录数:', COUNT(*) FROM config_access_logs
UNION ALL
SELECT 'admin_users 记录数:', COUNT(*) FROM admin_users
UNION ALL
SELECT 'auto_update_settings 记录数:', COUNT(*) FROM auto_update_settings
UNION ALL
SELECT 'cfips 记录数:', COUNT(*) FROM cfips
UNION ALL
SELECT 'cf_domains 记录数:', COUNT(*) FROM cf_domains;

-- ========================================================
-- 14. 数据库维护和优化建议
-- ========================================================

-- 定期维护建议 (可以根据需要定期执行)

-- 1. 清理过期的访问日志 (保留最近90天)
-- DELETE FROM config_access_logs WHERE created_at < datetime('now', '-90 days');

-- 2. 清理系统日志 (保留最近30天)
-- DELETE FROM system_logs WHERE created_at < datetime('now', '-30 days');

-- 3. 定期更新IP池 (删除超过7天的旧IP) - 如果使用IP池功能
-- DELETE FROM cfips WHERE created_at < datetime('now', '-7 days');

-- 4. 清理未激活用户 (例如超过30天未登录且无配置)
-- DELETE FROM users WHERE 
--   created_at < datetime('now', '-30 days') 
--   AND NOT EXISTS (SELECT 1 FROM configs WHERE user_id = users.id OR uuid = users.uuid);

-- 5. 优化数据库文件大小
-- VACUUM;

-- 6. 重建索引 (如果性能下降)
-- REINDEX;

-- ========================================================
-- 15. 兼容性说明
-- ========================================================

-- users 表字段说明：
--   username: 用户名，用于登录，唯一
--   email: 邮箱，可选，可用于找回密码
--   password_hash: 密码哈希值 (使用 SHA-256 + 盐值)

-- configs 表字段说明：
--   user_id: 用户ID，关联到users表的id，允许NULL表示公共配置或老数据
--   config_data: 存储原始配置字符串 (vmess://..., vless://...)
--   protocol: 协议类型，从配置字符串中自动解析
--   remark: 配置别名，从配置字符串中自动提取
--   domain_hosting: 域名托管服务，支持的值：
--     - Cloudflare, 阿里ESA, 腾讯Edgeone, AWS Cloudfront
--     - Gcore, Fastly, CacheFly, LightCDN, Vercel, Netlify
--     - 无 (不使用域名托管), 其他

-- 升级说明：
-- 1. 本脚本完全兼容现有系统
-- 2. 新增users表用于用户管理
-- 3. configs表中的user_id字段现在有实际的外键约束
-- 4. 原有数据保持不变，user_id为NULL的记录表示为公共配置
-- 5. 用户注册后需要通过认领或创建配置来获取UUID

-- 注意：在生产环境中部署前，请先在测试环境执行完整测试
