-- ========================================================
-- Cloudflare Worker 代理配置优选工具 - 数据库初始化脚本
-- 版本: v2.1.1
-- 作者: yangzifun.org
-- ========================================================

-- ========================================================
-- 1. 用户管理表 (管理员账户)
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

-- ========================================================
-- 2. 优选域名表
-- ========================================================
CREATE TABLE IF NOT EXISTS cf_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,          -- 优选域名
    remark TEXT,                          -- 备注说明
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    updated_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- ========================================================
-- 3. 配置表 (存储代理配置)
-- ========================================================
CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,                   -- 配置分组UUID
    config TEXT NOT NULL,                 -- 配置内容 (base64编码的协议链接)
    alias TEXT,                           -- 配置别名 (可选)
    address TEXT,                         -- 原始地址 (可选)
    port INTEGER,                         -- 端口 (可选)
    protocol_type TEXT,                   -- 协议类型 (vmess/vless/trojan/ss/ssr等)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- 为配置表添加索引提高查询性能
CREATE INDEX IF NOT EXISTS idx_configs_uuid ON configs(uuid);
CREATE INDEX IF NOT EXISTS idx_configs_protocol ON configs(protocol_type);

-- ========================================================
-- 4. IP池表 (存储优选IP地址)
-- ========================================================
CREATE TABLE IF NOT EXISTS cfips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,              -- IP地址 (IPv4/IPv6)
    ip_type TEXT NOT NULL,                -- IP类型 (v4/v6)
    carrier TEXT NOT NULL,                -- 运营商 (CT=电信, CU=联通, CM=移动)
    source TEXT DEFAULT 'unknown',        -- IP来源 (hostmonit_v4/hostmonit_v6/vps789等)
    latency INTEGER DEFAULT 0,            -- 延迟 (毫秒，可选)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- 为IP池表添加索引提高查询性能
CREATE INDEX IF NOT EXISTS idx_cfips_type ON cfips(ip_type);
CREATE INDEX IF NOT EXISTS idx_cfips_carrier ON cfips(carrier);
CREATE INDEX IF NOT EXISTS idx_cfips_source ON cfips(source);
CREATE INDEX IF NOT EXISTS idx_cfips_latency ON cfips(latency);

-- ========================================================
-- 5. 自动更新设置表
-- ========================================================
CREATE TABLE IF NOT EXISTS auto_update_settings (
    source TEXT PRIMARY KEY,              -- 来源标识
    enabled INTEGER NOT NULL DEFAULT 1,   -- 是否启用 (0=禁用, 1=启用)
    update_interval INTEGER DEFAULT 3600, -- 更新间隔 (秒，默认1小时)
    updated_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- ========================================================
-- 6. MFA备份码表
-- ========================================================
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,               -- 关联的用户名
    code TEXT NOT NULL,                   -- 备份码 (哈希值)
    used INTEGER DEFAULT 0,               -- 是否已使用 (0=未使用, 1=已使用)
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    used_at INTEGER DEFAULT 0,            -- 使用时间戳 (毫秒)
    FOREIGN KEY (username) REFERENCES admin_users(username) ON DELETE CASCADE
);

-- ========================================================
-- 7. 访问日志表 (记录配置访问统计)
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

-- 为访问日志表添加索引以优化查询性能
CREATE INDEX IF NOT EXISTS idx_access_logs_uuid ON config_access_logs(uuid);
CREATE INDEX IF NOT EXISTS idx_access_logs_date ON config_access_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_access_logs_type ON config_access_logs(query_type);
CREATE INDEX IF NOT EXISTS idx_access_logs_client_ip ON config_access_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_access_logs_uuid_date ON config_access_logs(uuid, created_at);

-- ========================================================
-- 8. 系统日志表 (记录操作日志)
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

-- ========================================================
-- 9. API访问统计表 (记录API调用频率)
-- ========================================================
CREATE TABLE IF NOT EXISTS api_access_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,               -- API端点路径
    method TEXT NOT NULL,                 -- HTTP方法
    count INTEGER DEFAULT 1,              -- 访问次数
    last_access INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000),
    created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INT) * 1000)
);

-- ========================================================
-- 10. 初始化数据
-- ========================================================

-- 初始化默认管理员账户
-- 用户名: admin
-- 密码: password (SHA-256哈希值)
INSERT OR IGNORE INTO admin_users (username, password_hash, mfa_enabled) VALUES 
('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 0);

-- 初始化默认优选域名
INSERT OR IGNORE INTO cf_domains (domain, remark) VALUES 
('cf.example.com', '默认优选域名'),
('cdn.example.net', '加速CDN专用域名');

-- 初始化自动更新配置
INSERT OR IGNORE INTO auto_update_settings (source, enabled, update_interval) VALUES 
('global_enabled', 1, 3600),           -- 全局开关
('hostmonit_v4', 1, 7200),             -- HostMonit IPv4 (默认2小时更新)
('hostmonit_v6', 0, 7200),             -- HostMonit IPv6 (默认禁用)
('vps789', 1, 10800),                  -- Vps789 (默认3小时更新)
('last_executed', 0, 0);               -- 上次执行时间戳

-- ========================================================
-- 11. 视图定义 (可选，用于复杂查询)
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

-- 创建热门配置视图
CREATE VIEW IF NOT EXISTS popular_configs AS
SELECT 
    uuid,
    COUNT(*) as access_count,
    SUM(CASE WHEN query_type = 'subscription' THEN 1 ELSE 0 END) as subscription_count,
    SUM(CASE WHEN query_type = 'api-generation' THEN 1 ELSE 0 END) as apigen_count,
    MIN(created_at) as first_access,
    MAX(created_at) as last_access,
    COUNT(DISTINCT client_ip) as unique_clients
FROM config_access_logs
GROUP BY uuid
ORDER BY access_count DESC;

-- ========================================================
-- 12. 查询系统信息
-- ========================================================

-- 显示所有表信息
SELECT '数据库表创建完成!' as message;

-- 显示表结构概览
SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';

-- 显示初始化数据统计
SELECT 'admin_users 记录数:' as table_name, COUNT(*) as record_count FROM admin_users
UNION ALL
SELECT 'cf_domains 记录数:', COUNT(*) FROM cf_domains
UNION ALL
SELECT 'auto_update_settings 记录数:', COUNT(*) FROM auto_update_settings;

-- ========================================================
-- 数据库优化建议
-- ========================================================

-- 1. 定期清理过期的访问日志 (保留最近90天)
-- DELETE FROM config_access_logs WHERE created_at < datetime('now', '-90 days');

-- 2. 定期清理系统日志 (保留最近30天)
-- DELETE FROM system_logs WHERE created_at < datetime('now', '-30 days');

-- 3. 定期更新IP池 (删除超过7天的旧IP)
-- DELETE FROM cfips WHERE created_at < datetime('now', '-7 days');

-- 4. 优化数据库文件大小
-- VACUUM;
