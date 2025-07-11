



1. D1 数据库设置：

   - 确保您的 Cloudflare Worker 已绑定 D1 数据库，且绑定变量名为 `DB`。

   - 在 D1 数据库中创建configs和cfips表（如果尚未创建）。可以使用以下 SQL 语句：



~~~sql

/* =================================================================
 *  D1 数据库建表 Schema (v3.3+)
 * ================================================================= */

-- 用于 `configs` 表的建表语句 (无变动)
-- 存储用户管理的基础配置
CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    config_data TEXT NOT NULL,
    protocol TEXT,
    remark TEXT,
    created_at INTEGER,
    updated_at INTEGER,
    UNIQUE (uuid, config_data)
);

-- 【已修改】用于 `cfips` 表的建表语句
-- 存储从 API 获取并缓存的 Cloudflare 优选 IP
CREATE TABLE IF NOT EXISTS cfips (
    ip TEXT PRIMARY KEY,
    ip_type TEXT NOT NULL, -- 'v4' or 'v6'
    carrier TEXT NOT NULL, -- 'CM', 'CU', 'CT'
    created_at INTEGER NOT NULL
);

~~~