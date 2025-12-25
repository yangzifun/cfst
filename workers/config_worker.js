/* =================================================================
 *  Cloudflare Worker: Config Manager + User System
 *  功能：用户登录注册、配置存储管理、订阅管理、统计分析
 *  修改：增加登录后关联UUID功能，支持所有UUID的总览及单个UUID管理
 *  解决：登录按钮显示问题，登录按钮位置，关联UUID按钮不可点击问题
 * ================================================================= */

// =================================================================
//  GLOBAL UTILITIES (后端工具函数)
// =================================================================

function utf8_to_b64(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function toSolidBytes(match, p1) {
            return String.fromCharCode(parseInt(p1, 16));
        }));
}

function b64_to_utf8(str) {
    try {
        return decodeURIComponent(atob(str).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        throw new Error("无效的 Base64 字符串");
    }
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
        status: status,
        headers: { 
            'Content-Type': 'application/json;charset=UTF-8',
            'Access-Control-Allow-Origin': '*'
        },
    });
}

function htmlResponse(html, status = 200) {
    return new Response(html, {
        status: status,
        headers: { 
            'Content-Type': 'text/html;charset=UTF-8',
            'Access-Control-Allow-Origin': '*'
        },
    });
}

function getProtocol(configStr) {
    if (!configStr || typeof configStr !== 'string') return 'unknown';
    if (configStr.startsWith('vmess://')) return 'vmess';
    if (configStr.startsWith('vless://')) return 'vless';
    if (configStr.startsWith('trojan://')) return 'trojan';
    if (configStr.startsWith('hysteria2://')) return 'hysteria2';
    if (configStr.startsWith('tuic://')) return 'tuic';
    if (configStr.startsWith('anytls://')) return 'anytls';
    if (configStr.startsWith('socks5://')) return 'socks5';
    if (configStr.startsWith('any-reality://')) return 'any-reality';
    if (configStr.startsWith('ss://')) return 'ss';
    return 'unknown';
}

function extractRemarkFromConfig(configStr, protocol) {
    try {
        if (protocol === 'vmess') {
            const vmessObj = JSON.parse(b64_to_utf8(configStr.substring(8)));
            return vmessObj.ps || vmessObj.remark || null;
        } else if (protocol === 'vless' || protocol === 'trojan' || 
                  protocol === 'hysteria2' || protocol === 'tuic' ||
                  protocol === 'anytls' || protocol === 'socks5' ||
                  protocol.startsWith('any-reality') || protocol.startsWith('ss')) {
            const url = new URL(configStr);
            if (url.hash) return decodeURIComponent(url.hash.substring(1));
        }
    } catch (e) { /* ignore parse errors */ }
    return null;
}

// 创建或验证Session (已修改，包含 userUuid)
async function generateSessionToken(userId, userUuid, username, env) {
    const token = crypto.randomUUID();
    const sessionData = {
        userId,
        userUuid, // 为session添加用户UUID (用户自身的UUID)
        username,
        createdAt: Date.now(),
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7天过期
    };
  
    // 存储session到KV (如果env有KV的话)
    if (env.SESSIONS) {
        await env.SESSIONS.put(`session:${token}`, JSON.stringify(sessionData), {
            expirationTtl: 7 * 24 * 60 * 60 // 7天
        });
    }
  
    return { token, sessionData };
}

async function validateSessionToken(token, env) {
    if (!token) return null;
  
    if (env.SESSIONS) {
        const sessionData = await env.SESSIONS.get(`session:${token}`, 'json');
        if (sessionData && sessionData.expiresAt > Date.now()) {
            return sessionData;
        }
    }
    return null;
}

// =================================================================
//  DATABASE LOGIC (数据库操作 - 包含用户功能)
// =================================================================

// 用户认证函数 (已修改，返回 userUuid)
async function authenticateUser(username, password, env) {
    const db = env.DB;
    if (!db) return { success: false, error: "数据库未连接" };
  
    try {
        // SELECT 语句中加入 uuid (用户自身的UUID)
        const user = await db.prepare(
            'SELECT id, uuid, username, password_hash FROM users WHERE username = ?'
        ).bind(username).first();
      
        if (!user) {
            return { success: false, error: "用户不存在" };
        }
      
        // SHA-256加密验证
        const hash = await sha256(password);
        if (hash === user.password_hash) {
            return { 
                success: true, 
                user: { id: user.id, uuid: user.uuid, username: user.username } // 返回 userUuid (用户自身的UUID)
            };
        } else {
            return { success: false, error: "密码错误" };
        }
    } catch (e) {
        return { success: false, error: "数据库错误: " + e.message };
    }
}

// 用户注册函数（已修改：生成并插入 uuid 字段）
async function registerUser(username, password, email = null, env) {
    const db = env.DB;
    if (!db) return { success: false, error: "数据库未连接" };
  
    try {
        // 检查用户名是否已存在
        const existingUser = await db.prepare(
            'SELECT id FROM users WHERE username = ?'
        ).bind(username).first();
      
        if (existingUser) {
            return { success: false, error: "用户名已存在" };
        }
      
        // 检查邮箱是否已存在（如果提供邮箱）
        if (email) {
            const existingEmail = await db.prepare(
                'SELECT id FROM users WHERE email = ?'
            ).bind(email).first();
          
            if (existingEmail) {
                return { success: false, error: "邮箱已被注册" };
            }
        }
      
        // SHA-256加密密码
        const passwordHash = await sha256(password);
      
        // 生成用户UUID (用户自身的UUID)
        const userUuid = crypto.randomUUID(); 
        const now = Math.floor(Date.now() / 1000);
      
        // INSERT 语句中加入 uuid
        const result = await db.prepare(
            'INSERT INTO users (uuid, username, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(userUuid, username, email, passwordHash, now, now).run();
      
        if (result?.lastInsertId) {
            return { 
                success: true, 
                userId: result.lastInsertId,
                userUuid: userUuid, // 返回生成的 userUuid (用户自身的UUID)
                message: "注册成功" 
            };
        } else {
            return { success: false, error: "注册失败" };
        }
    } catch (e) {
        console.error("注册错误:", e.message);
        return { success: false, error: "数据库错误: " + e.message };
    }
}

// SHA-256加密函数
async function sha256(message) {
    const msgUint8 = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// 获取用户自己的Config UUID列表 (此处的UUID是指用户拥有的Config UUID，而非用户的userUuid)
async function getUserUuids(userId, env) {
    const db = env.DB;
    if (!db) return [];
  
    try {
        const stmt = db.prepare(
            'SELECT DISTINCT uuid FROM configs WHERE user_id = ? ORDER BY uuid ASC'
        );
        const { results } = await stmt.bind(userId).all();
        return results.map(r => r.uuid);
    } catch (e) {
        console.error("获取用户Config UUID失败:", e.message);
        return [];
    }
}

// 获取用户统计信息 (已修改，包含 userUuid)
async function getUserStats(userId, env) {
    const db = env.DB;
    if (!db) return null;
  
    try {
        // 用户基本信息，加入 uuid (用户自身的UUID)
        const userInfo = await db.prepare(
            'SELECT id, uuid, username, email, created_at FROM users WHERE id = ?'
        ).bind(userId).first();
      
        if (!userInfo) return null;
      
        // 配置统计
        const configStats = await db.prepare(`
            SELECT 
                COUNT(*) as total_configs,
                COUNT(DISTINCT uuid) as owned_uuids,
                GROUP_CONCAT(DISTINCT protocol) as protocols,
                COUNT(DISTINCT domain_hosting) as hosting_types
            FROM configs 
            WHERE user_id = ?
        `).bind(userId).first();
      
        // 访问统计
        const accessStats = await db.prepare(`
            SELECT 
                COUNT(*) as total_access,
                SUM(CASE WHEN query_type = 'subscription' THEN 1 ELSE 0 END) as subscription_count,
                SUM(CASE WHEN query_type = 'api-generation' THEN 1 ELSE 0 END) as apigen_count,
                MIN(cal.created_at) as first_access,
                MAX(cal.created_at) as last_access
            FROM config_access_logs cal
            JOIN configs c ON cal.uuid = c.uuid
            WHERE c.user_id = ?
        `).bind(userId).first();
      
        return {
            user: {
                id: userInfo.id,
                uuid: userInfo.uuid, // 返回用户的userUuid
                username: userInfo.username,
                email: userInfo.email,
                created_at: userInfo.created_at
            },
            configs: {
                total: configStats?.total_configs || 0,
                uuids: configStats?.owned_uuids || 0, // 用户拥有的configs.uuid数量
                protocols: configStats?.protocols ? configStats.protocols.split(',').filter(Boolean) : [],
                hosting_types: configStats?.hosting_types || 0
            },
            access: {
                total: accessStats?.total_access || 0,
                subscription: accessStats?.subscription_count || 0,
                apigen: accessStats?.apigen_count || 0,
                first_access: accessStats?.first_access,
                last_access: accessStats?.last_access
            }
        };
    } catch (e) {
        console.error("获取用户统计失败:", e.message);
        return null;
    }
}

// NEW: Helper to check if a Config UUID exists and if it's already owned
async function checkConfigUuidOwnership(configUuid, userId, env) {
    const db = env.DB;
    if (!db) return { exists: false, ownedByUser: false, ownedByOther: false, message: "数据库未连接" };

    try {
        // Find if any config exists with this uuid
        const configExistsResult = await db.prepare(
            'SELECT user_id FROM configs WHERE uuid = ? LIMIT 1'
        ).bind(configUuid).first();

        if (!configExistsResult) { // Config UUID does not exist as a config (empty)
            return { exists: false, ownedByUser: false, ownedByOther: false, message: "Config UUID 不存在任何配置" };
        }

        if (configExistsResult.user_id === null) { // Exists, but unowned
            return { exists: true, ownedByUser: false, ownedByOther: false, message: "Config UUID 可关联" };
        } else if (configExistsResult.user_id === userId) { // Exists and owned by current user
            return { exists: true, ownedByUser: true, ownedByOther: false, message: "该 Config UUID 已是您的" };
        } else { // Exists and owned by another user
            return { exists: true, ownedByUser: false, ownedByOther: true, message: "该 Config UUID 已被其他用户关联" };
        }
    } catch (e) {
        console.error("检查 Config UUID 归属失败:", e.message);
        return { exists: false, ownedByUser: false, ownedByOther: false, message: "数据库错误: " + e.message };
    }
}

// MODIFIED: fetchConfigsByUuidFromDB to support '_all_' for aggregated config list
async function fetchConfigsByUuidFromDB(configUuid, env, userId = null) {
    const db = env.DB;
    if (!db) return [];
  
    try {
        let stmt;
        if (configUuid === '_all_') { // New logic for fetching all configs owned by the user
            if (userId === null) return []; // Authenticated calls *should* have a userId
            stmt = db.prepare(
                'SELECT id, uuid, config_data, protocol, remark, domain_hosting FROM configs WHERE user_id = ? ORDER BY uuid ASC, id ASC'
            ).bind(userId);
        } else if (userId !== null) {
            // User can only see their own configs
            stmt = db.prepare(
                'SELECT id, uuid, config_data, protocol, remark, domain_hosting FROM configs WHERE uuid = ? AND user_id = ? ORDER BY id ASC'
            ).bind(configUuid, userId);
        } else {
            // Fallback for public access, e.g., subscriptions. No user_id filter applies.
            stmt = db.prepare(
                'SELECT id, uuid, config_data, protocol, remark, domain_hosting FROM configs WHERE uuid = ? ORDER BY id ASC'
            ).bind(configUuid);
        }
      
        const { results } = await stmt.all();
        return results;
    } catch (e) { 
        console.error("获取配置失败:", e.message);
        return []; 
    }
}

// NEW: fetchUserAggregatedStatsFromDB for 'overview' mode
async function fetchUserAggregatedStatsFromDB(userId, env, days = 30) {
    const db = env.DB;
    if (!db) return { success: false, error: "数据库未连接" };

    try {
        // Aggregated stats for ALL configs owned by the user
        const totalStats = await db.prepare(`
            SELECT 
                COUNT(*) as total_access,
                SUM(CASE WHEN cal.query_type = 'subscription' THEN 1 ELSE 0 END) as subscription_count,
                SUM(CASE WHEN cal.query_type = 'api-generation' THEN 1 ELSE 0 END) as apigen_count,
                MIN(cal.created_at) as first_access,
                MAX(cal.created_at) as last_access
            FROM config_access_logs cal
            JOIN configs c ON cal.uuid = c.uuid
            WHERE c.user_id = ?
        `).bind(userId).first();

        // Today's stats
        const today = new Date().toISOString().split('T')[0];
        const todayStats = await db.prepare(`
            SELECT 
                COUNT(*) as today_total,
                SUM(CASE WHEN cal.query_type = 'subscription' THEN 1 ELSE 0 END) as today_subscription,
                SUM(CASE WHEN cal.query_type = 'api-generation' THEN 1 ELSE 0 END) as today_apigen
            FROM config_access_logs cal
            JOIN configs c ON cal.uuid = c.uuid
            WHERE c.user_id = ? AND DATE(cal.created_at) = ?
        `).bind(userId, today).first();

        // Daily stats
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);
        const startDateStr = startDate.toISOString().split('T')[0];

        const dailyStats = await db.prepare(`
            SELECT 
                DATE(cal.created_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN cal.query_type = 'subscription' THEN 1 ELSE 0 END) as subscription,
                SUM(CASE WHEN cal.query_type = 'api-generation' THEN 1 ELSE 0 END) as api_generation
            FROM config_access_logs cal
            JOIN configs c ON cal.uuid = c.uuid
            WHERE c.user_id = ? AND DATE(cal.created_at) >= ?
            GROUP BY DATE(cal.created_at)
            ORDER BY date ASC
        `).bind(userId, startDateStr).all();

        // Recent logs for all UUIDs
        const recentLogs = await db.prepare(`
            SELECT 
                cal.uuid, cal.query_type, cal.client_ip, cal.user_agent, cal.created_at
            FROM config_access_logs cal
            JOIN configs c ON cal.uuid = c.uuid
            WHERE c.user_id = ?
            ORDER BY cal.created_at DESC
            LIMIT 50
        `).bind(userId).all();

        return {
            success: true,
            uuid: '_all_', // Indicate this is aggregated stats
            total_access: totalStats?.total_access || 0,
            subscription_count: totalStats?.subscription_count || 0,
            apigen_count: totalStats?.apigen_count || 0,
            first_access: totalStats?.first_access,
            last_access: totalStats?.last_access,
            today_total: todayStats?.today_total || 0,
            today_subscription: todayStats?.today_subscription || 0,
            today_apigen: todayStats?.today_apigen || 0,
            daily_stats: dailyStats?.results || [],
            recent_logs: recentLogs?.results || []
        };
    } catch (e) {
        console.error("获取用户聚合统计失败:", e.message);
        return { success: false, error: "数据库查询失败: " + e.message };
    }
}

// 获取UUID访问统计（单个UUID）
async function fetchUuidAccessStatsFromDB(uuid, env, days = 30, userId = null) {
    const db = env.DB;
    if (!db) return { success: false, error: "数据库未连接" };
  
    try {
        // 检查权限：用户只能查看自己拥有的Config UUID统计
        if (userId !== null) {
            const ownership = await db.prepare(
                'SELECT 1 FROM configs WHERE uuid = ? AND user_id = ? LIMIT 1'
            ).bind(uuid, userId).first();
          
            if (!ownership) {
                return { 
                    success: false, 
                    error: "无权查看此UUID的统计信息" 
                };
            }
        }
      
        // 获取总访问统计
        const totalStats = await db.prepare(`
            SELECT 
                COUNT(*) as total_access,
                SUM(CASE WHEN query_type = 'subscription' THEN 1 ELSE 0 END) as subscription_count,
                SUM(CASE WHEN query_type = 'api-generation' THEN 1 ELSE 0 END) as apigen_count,
                MIN(created_at) as first_access,
                MAX(created_at) as last_access
            FROM config_access_logs 
            WHERE uuid = ?
        `).bind(uuid).first();
      
        // 获取今日访问统计
        const today = new Date().toISOString().split('T')[0];
        const todayStats = await db.prepare(`
            SELECT 
                COUNT(*) as today_total,
                SUM(CASE WHEN query_type = 'subscription' THEN 1 ELSE 0 END) as today_subscription,
                SUM(CASE WHEN query_type = 'api-generation' THEN 1 ELSE 0 END) as today_apigen
            FROM config_access_logs 
            WHERE uuid = ? AND DATE(created_at) = ?
        `).bind(uuid, today).first();
      
        // 获取按日统计（最近指定天数）
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);
        const startDateStr = startDate.toISOString().split('T')[0];
      
        const dailyStats = await db.prepare(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN query_type = 'subscription' THEN 1 ELSE 0 END) as subscription,
                SUM(CASE WHEN query_type = 'api-generation' THEN 1 ELSE 0 END) as api_generation
            FROM config_access_logs 
            WHERE uuid = ? AND DATE(created_at) >= ?
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `).bind(uuid, startDateStr).all();
      
        // 获取最近50条访问记录
        const recentLogs = await db.prepare(`
            SELECT 
                uuid, query_type, client_ip, user_agent, created_at
            FROM config_access_logs 
            WHERE uuid = ?
            ORDER BY created_at DESC
            LIMIT 50
        `).bind(uuid).all();
      
        return {
            success: true,
            uuid: uuid,
            total_access: totalStats?.total_access || 0,
            subscription_count: totalStats?.subscription_count || 0,
            apigen_count: totalStats?.apigen_count || 0,
            first_access: totalStats?.first_access,
            last_access: totalStats?.last_access,
            today_total: todayStats?.today_total || 0,
            today_subscription: todayStats?.today_subscription || 0,
            today_apigen: todayStats?.today_apigen || 0,
            daily_stats: dailyStats?.results || [],
            recent_logs: recentLogs?.results || []
        };
      
    } catch (e) {
        console.error("获取UUID访问统计失败:", e.message);
        return { 
            success: false, 
            error: "数据库查询失败: " + e.message 
        };
    }
}

// 订阅输出 (Raw Base64) - 订阅链接不应要求用户认证，但可以通过user_id限制访问（若必要）
async function handleRawSubscription(uuid, env) {
    if (!uuid) return jsonResponse({ error: 'UUID Required' }, 400);
    const configs = await fetchConfigsByUuidFromDB(uuid, env, null); // 这里不传入userId，意味着任何拥有UUID的人都能订阅
    
    if (!configs || configs.length === 0) return new Response("UUID Not Found or Empty", { status: 404 });
  
    const configList = configs.map(c => c.config_data);
    return new Response(btoa(configList.join('\n')), {
        status: 200,
        headers: { 
            'Content-Type': 'text/plain;charset=UTF-8', 
            'Subscription-User-Info': 'upload=0; download=0; total=10737418240000; expire=2524608000' 
        },
    });
}

// =================================================================
//  API HANDLERS (接口逻辑 - 包含用户认证)
// =================================================================

// 用户登录 (已修改，包含 userUuid)
async function handleUserLogin(request, env) {
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效 JSON' }, 400); }
  
    const { username, password } = body;
    if (!username || !password) {
        return jsonResponse({ error: '用户名和密码不能为空' }, 400);
    }
  
    const authResult = await authenticateUser(username, password, env);
    if (!authResult.success) {
        return jsonResponse({ error: authResult.error }, 401);
    }
  
    // 生成session token，传入 userUuid (用户自身的UUID)
    const { token, sessionData } = await generateSessionToken(
        authResult.user.id, 
        authResult.user.uuid,     // 传入 userUuid
        authResult.user.username, 
        env
    );
  
    return jsonResponse({
        success: true,
        token: token,
        user: { 
            id: authResult.user.id, 
            uuid: authResult.user.uuid, // 返回 userUuid
            username: authResult.user.username 
        },
        message: "登录成功"
    });
}

// 用户注册 (已修改，包含 userUuid)
async function handleUserRegister(request, env) {
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效 JSON' }, 400); }
  
    const { username, password, email } = body;
    if (!username || !password) {
        return jsonResponse({ error: '用户名和密码不能为空' }, 400);
    }
  
    if (username.length < 3 || username.length > 20) {
        return jsonResponse({ error: '用户名长度必须为3-20个字符' }, 400);
    }
  
    if (password.length < 6) {
        return jsonResponse({ error: '密码长度至少6个字符' }, 400);
    }
  
    // 可选email验证
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return jsonResponse({ error: '邮箱格式不正确' }, 400);
    }
  
    const registerResult = await registerUser(username, password, email, env);
    if (!registerResult.success) {
        return jsonResponse({ error: registerResult.error }, 400);
    }
  
    // 自动登录，传入 userUuid (用户自身的UUID)
    const { token, sessionData } = await generateSessionToken(
        registerResult.userId, 
        registerResult.userUuid, // 传入 userUuid
        username, 
        env
    );
  
    return jsonResponse({
        success: true,
        token: token,
        user: { 
            id: registerResult.userId, 
            uuid: registerResult.userUuid, // 返回 userUuid
            username: username 
        },
        message: registerResult.message
    });
}

// 用户登出
async function handleUserLogout(request, env) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    // 强制检查token有效性，避免无意义的KV操作
    const session = await validateSessionToken(token, env);
    if (session && env.SESSIONS) {
        await env.SESSIONS.delete(`session:${token}`);
    }
  
    return jsonResponse({
        success: true,
        message: "登出成功"
    });
}

// 获取当前用户信息 (已修改，包含 userUuid)
async function handleGetCurrentUser(request, env) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期' }, 401);
    }
  
    const userStats = await getUserStats(session.userId, env); // getUserStats内部已处理userUuid
    if (!userStats) {
        return jsonResponse({ error: '用户信息获取失败' }, 500);
    }
  
    return jsonResponse({
        success: true,
        user: userStats.user,
        stats: {
            configs: userStats.configs,
            access: userStats.access
        }
    });
}

// 获取用户Config UUID列表
async function handleGetUserUuids(request, env) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期' }, 401);
    }
  
    const uuids = await getUserUuids(session.userId, env);
  
    return jsonResponse({
        success: true,
        uuids: uuids,
        count: uuids.length
    });
}

// NEW: handleLinkConfigUuid API handler
async function handleLinkConfigUuid(request, env) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期，无权关联 Config UUID' }, 401);
    }

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效 JSON' }, 400); }
    const { configUuid } = body; 
    if (!configUuid) return jsonResponse({ error: 'Config UUID 不能为空' }, 400);

    const ownership = await checkConfigUuidOwnership(configUuid, session.userId, env);

    if (!ownership.exists) {
        return jsonResponse({ success: false, error: ownership.message || "Config UUID 不存在任何配置" }, 404);
    }
    if (ownership.ownedByUser) {
        return jsonResponse({ success: false, message: "该 Config UUID 已是您的，无需重复关联。" }, 200); // 200 OK because it's already "successful" in a sense
    }
    if (ownership.ownedByOther) {
        return jsonResponse({ success: false, error: ownership.message || "该 Config UUID 已被其他用户关联，无法直接关联。" }, 403);
    }

    try {
        const res = await env.DB.prepare(
            'UPDATE configs SET user_id = ?, updated_at = ? WHERE uuid = ? AND user_id IS NULL'
        ).bind(session.userId, Date.now(), configUuid).run();
      
        if (res.changes > 0) {
            return jsonResponse({ success: true, message: `成功关联 Config UUID: ${configUuid}` });
        } else {
            return jsonResponse({ success: false, error: '关联失败，可能是 Config UUID 不存在或已被关联。' }, 400);
        }
    } catch (e) {
        return jsonResponse({ error: e.message }, 500);
    }
}

// 添加配置（需要用户身份）
async function handleAddConfig(request, env) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    // 权限验证
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期，无权添加配置' }, 401);
    }

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效 JSON' }, 400); }
    const { uuid, config_data, domain_hosting = 'Cloudflare' } = body; // uuid here is configUuid
    if (!uuid || !config_data) return jsonResponse({ error: '字段缺失: uuid 和 config_data 不能为空' }, 400);
  
    // 验证域名托管参数
    const validDomainHostings = [
        'Cloudflare', '阿里ESA', '腾讯Edgeone', 'AWS Cloudfront', 
        'Gcore', 'Fastly', 'CacheFly', 'LightCDN', 'Vercel', 'Netlify',
        '无', '其他'
    ];
    const hostingValue = validDomainHostings.includes(domain_hosting) ? domain_hosting : 'Cloudflare';
  
    const lines = config_data.split('\n').map(l => l.trim()).filter(Boolean);
    const stmts = [];
    for (const line of lines) {
        const p = getProtocol(line);
        if (p === 'unknown') continue;
        const remark = extractRemarkFromConfig(line, p);
      
        const stmt = env.DB.prepare(
            'INSERT INTO configs (uuid, user_id, config_data, protocol, remark, domain_hosting, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(uuid,config_data) DO NOTHING'
        ).bind(
            uuid, 
            session.userId, // 关联登录用户的ID
            line, 
            p, 
            remark, 
            hostingValue, 
            Date.now(), 
            Date.now()
        );
        stmts.push(stmt);
    }
  
    if (stmts.length === 0) return jsonResponse({ error: '无有效配置解析或重复添加' }, 400);
    const result = await env.DB.batch(stmts);
    return jsonResponse({ success: true, message: `成功添加 ${result.length} 条配置` });
}

// 更新配置（需要权限验证）
async function handleUpdateConfig(request, env) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效JSON' }, 400); }
    const { id, config_data, domain_hosting = 'Cloudflare' } = body;

    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期，无权更新配置' }, 401);
    }
    if (!id || !config_data) return jsonResponse({ error: '字段缺失: id 和 config_data 不能为空' }, 400);
  
    const protocol = getProtocol(config_data);
    if(protocol === 'unknown') return jsonResponse({ error: '不支持的配置格式' }, 400);
    const remark = extractRemarkFromConfig(config_data, protocol);
  
    // 验证域名托管参数
    const validDomainHostings = [
        'Cloudflare', '阿里ESA', '腾讯Edgeone', 'AWS Cloudfront', 
        'Gcore', 'Fastly', 'CacheFly', 'LightCDN', 'Vercel', 'Netlify',
        '无', '其他'
    ];
    const hostingValue = validDomainHostings.includes(domain_hosting) ? domain_hosting : 'Cloudflare';
  
    try {
        // 检查权限：用户只能更新自己拥有的配置
        const res = await env.DB.prepare(
            'UPDATE configs SET config_data = ?, protocol = ?, remark = ?, domain_hosting = ?, updated_at = ? WHERE id = ? AND user_id = ?'
        ).bind(config_data, protocol, remark, hostingValue, Date.now(), id, session.userId).run();
      
        return res.changes > 0 ? jsonResponse({ success: true, message: 'Updated' }) : jsonResponse({ error: '未变更或无权限' }, 403);
    } catch(e) { return jsonResponse({ error: e.message }, 500); }
}

// 获取配置（支持用户过滤和_all_聚合）
async function handleGetConfigs(configUuid, env, request) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期，无权查看配置' }, 401);
    }

    const userId = session.userId;
    // fetchConfigsByUuidFromDB handles the '_all_' case or single UUID case.
    const results = await fetchConfigsByUuidFromDB(configUuid, env, userId);

    if (results.length === 0) {
        // If not found, but call was authenticated and authorized, return 404 with empty configs
        return jsonResponse({ configUuid, configs: [], message: '未找到相关配置或无权访问' }, 404);
    }
    return jsonResponse({ configUuid, configs: results });
}

// 获取UUID统计（需要权限验证，支持_all_聚合）
async function handleGetUuidStats(configUuid, env, request) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期，无权查看统计' }, 401);
    }
    if (!configUuid) return jsonResponse({ error: 'Config UUID Required' }, 400);
  
    const userId = session.userId;
    const url = new URL(request.url);
    const days = url.searchParams.get('days') || 30;
    
    let stats;
    if (configUuid === '_all_') { // Requesting aggregated stats for all user's Config UUIDs
        stats = await fetchUserAggregatedStatsFromDB(userId, env, parseInt(days));
    } else { // Requesting stats for a single Config UUID
        stats = await fetchUuidAccessStatsFromDB(configUuid, env, parseInt(days), userId);
    }
  
    if (!stats.success && stats.error === "无权查看此UUID的统计信息") {
        return jsonResponse({ error: stats.error }, 403);
    } else if (!stats.success) {
        return jsonResponse({ error: stats.error || "获取统计信息失败" }, 500);
    }
    return jsonResponse(stats);
}

// 删除配置（需要权限验证）
async function handleDelete(type, value, env, request) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const session = await validateSessionToken(token, env);
  
    if (!session) {
        return jsonResponse({ error: '未登录或会话已过期，无权删除配置' }, 401);
    }

    try {
        let res;
        if (type === 'id') {
            res = await env.DB.prepare(
                'DELETE FROM configs WHERE id = ? AND user_id = ?'
            ).bind(value, session.userId).run();
        } else if (type === 'uuid') { // 删除某个configUuid下的所有配置
            res = await env.DB.prepare(
                'DELETE FROM configs WHERE uuid = ? AND user_id = ?'
            ).bind(value, session.userId).run();
        } else {
            return jsonResponse({ success: false, message: '无效的删除类型' }, 400);
        }
      
        return res.changes > 0 ? jsonResponse({ success: true, message: `成功删除 ${res.changes} 条` }) : jsonResponse({ success: false, message: '未找到或无权限删除' }, 403);
    } catch (e) {
        return jsonResponse({ error: e.message }, 500);
    }
}

// =================================================================
//  MAIN ROUTER
// =================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        const DOMAIN_NAME = url.origin;

        const manageConfigPath = new URLPattern({ pathname: '/manage/configs/:configUuid' }); // For single or _all_ config UUID list/delete
        const manageIDPath = new URLPattern({ pathname: '/manage/configs/id/:id' });
        const subUUIDPath = new URLPattern({ pathname: '/sub/:uuid' });
        const uuidStatsPath = new URLPattern({ pathname: '/manage/stats/:configUuid' }); // For single or _all_ config UUID stats

        try {
            // 用户认证相关API
            if (method === 'POST' && path === '/api/auth/login') {
                return await handleUserLogin(request, env);
            }
          
            if (method === 'POST' && path === '/api/auth/register') {
                return await handleUserRegister(request, env);
            }
          
            if (method === 'POST' && path === '/api/auth/logout') {
                return await handleUserLogout(request, env);
            }
          
            if (method === 'GET' && path === '/api/auth/user') {
                return await handleGetCurrentUser(request, env);
            }
          
            if (method === 'GET' && path === '/api/user/uuids') {
                return await handleGetUserUuids(request, env);
            }
          
            // NEW: Link Config UUID API
            if (method === 'POST' && path === '/api/user/link-config-uuid') {
                return await handleLinkConfigUuid(request, env);
            }
          
            // 主页面
            if (method === 'GET') {
                if (path === '/' || path === '/index.html') {
                    return htmlResponse(managePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME));
                }
              
                if (path === '/login.html') {
                    return htmlResponse(loginPageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME));
                }
              
                if (path === '/register.html') {
                    return htmlResponse(registerPageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME));
                }
              
                // 订阅链接，非用户管理功能，不做user_id过滤
                const subMatch = subUUIDPath.exec(url); // path should be /sub/:uuid
                if (subMatch) {
                    if (env.DB) {
                        ctx.waitUntil(env.DB.prepare(
                            'INSERT INTO config_access_logs (uuid, query_type, client_ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?)'
                        ).bind(subMatch.pathname.groups.uuid, 'subscription', request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'), request.headers.get('User-Agent'), new Date().toISOString()).run());
                    }
                    return await handleRawSubscription(subMatch.pathname.groups.uuid, env);
                }

                // 配置管理页面的API需要认证
                const configMatch = manageConfigPath.exec(url);
                if (configMatch) {
                    const requestedConfigUuid = configMatch.pathname.groups.configUuid;
                    if (requestedConfigUuid !== '_all_' && env.DB) { // Only log if it's a specific UUID, not the aggregation placeholder
                        ctx.waitUntil(env.DB.prepare(
                            'INSERT INTO config_access_logs (uuid, query_type, client_ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?)'
                        ).bind(requestedConfigUuid, 'api-generation', request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'), request.headers.get('User-Agent'), new Date().toISOString()).run());
                    }
                    return await handleGetConfigs(requestedConfigUuid, env, request);
                }
              
                const statsMatch = uuidStatsPath.exec(url);
                if (statsMatch) {
                    return await handleGetUuidStats(statsMatch.pathname.groups.configUuid, env, request);
                }
            }

            // 配置管理API（需要认证）
            if (method === 'POST' && path === '/manage/configs') {
                return await handleAddConfig(request, env);
            }
          
            if (method === 'PUT' && path === '/manage/configs') {
                return await handleUpdateConfig(request, env);
            }
          
            if (method === 'DELETE') {
                const idMatch = manageIDPath.exec(url);
                if (idMatch) return await handleDelete('id', idMatch.pathname.groups.id, env, request);
                const configUuidMatch = manageConfigPath.exec(url); 
                if (configUuidMatch) return await handleDelete('uuid', configUuidMatch.pathname.groups.configUuid, env, request);
            }

            return new Response('404 Not Found', { status: 404 });
        } catch (err) {
            console.error("Worker Error:", err.message, err.stack);
            return new Response("Error: " + err.message, { status: 500 });
        }
    }
};

// =================================================================
//  FRONTEND CONTENT (包含用户登录注册界面)
// =================================================================
// 全局样式（更新）
const newGlobalStyle = `
html { font-size: 87.5%; } body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.app-header {
    width: 100%;
    padding: 15px 20px;
    background-color: #f8f9fa;
    border-bottom: 1px solid #E8EBED;
    display: flex;
    justify-content: space-between; /* Pushes logo left, auth-controls right */
    align-items: center;
    box-sizing: border-box;
}
.app-header .logo {
    font-size: 1.5rem;
    font-weight: bold;
    color: #3d474d;
}
.auth-controls {
    display: flex;
    align-items: center;
    gap: 15px; /* Space between login/user info */
}
.user-info-panel-header { /* Style adjustments for header user info */
    display: flex;
    align-items: center;
    background: none; /* Override old user-info-panel style */
    padding: 0;
    margin-bottom: 0;
    color: #3d474d;
}
.user-info-panel-header .user-avatar { /* Specific avatar for header */
    width: 32px;
    height: 32px;
    font-size: 1rem;
    margin: 0;
    flex-shrink: 0;
    background: #667eea; /* Background color of the avatar itself */
    color: white; /* Text color of the initial */
}
.nav-grid-header { /* For buttons inside header user info */
    display: flex;
    gap: 8px;
    margin-left: 15px;
}
.container { width: 100%; min-height: calc(100vh - 60px); display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 20px 20px; box-sizing: border-box; } /* Adjusted padding and min-height for header */
.content-group { width: 100%; max-width: 1000px; text-align: center; z-index: 10; box-sizing: border-box; }
.profile-name { font-size: 2.2rem; color: #3d474d; margin-bottom: 10px; font-weight: bold;}
.profile-quote { color: #89949B; margin-bottom: 27px; min-height: 1.2em; }
.nav-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-bottom: 27px; }
.nav-btn { display: inline-flex; align-items: center; justify-content: center; padding: 8px 16px; text-align: center; background: #E8EBED; border: 2px solid #89949B; border-radius: 4px; color: #5a666d; text-decoration: none !important; font-weight: 500; font-size: 0.95rem; line-height: 1.2; transition: all 0.3s; white-space: nowrap; cursor: pointer; box-sizing: border-box; }
.nav-btn:hover:not(:disabled) { background: #89949B; color: white; }
.nav-btn:disabled { opacity: 0.6; cursor: not-allowed;}
.nav-btn.primary { background-color: #5a666d; color: white; border-color: #5a666d;}
.nav-btn.primary:hover:not(:disabled) { background-color: #3d474d; }
.nav-btn.active { 
    background-color: #5a666d; 
    color: white; 
    border-color: #5a666d;
}
.card { background: #f8f9fa; border: 1px solid #E8EBED; border-radius: 8px; padding: 24px; margin-bottom: 24px; text-align: left; }
.card h2 { font-size: 1.5rem; color: #3d474d; margin-top: 0; margin-bottom: 20px; text-align: center;}
.form-group { margin-bottom: 16px; }
.form-group label { display: block; color: #5a666d; font-weight: 500; margin-bottom: 8px; font-size: 0.9rem;}
textarea, input[type="text"], input[type="number"], input[type="password"], input[type="email"], select { width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px; background: #fff; font-family: inherit; font-size: 0.9rem; box-sizing: border-box; resize: vertical; margin-bottom: 5px;}
textarea:focus, input:focus, select:focus { outline: none; border-color: #3d474d; }
.info-box { background-color: #e8ebed; color: #5a666d; border-left: 4px solid #89949B; padding: 12px 16px; border-radius: 4px; font-size: 0.85rem; text-align: left; line-height: 1.5; margin: 16px 0; }
.footer { margin-top: 40px; text-align: center; color: #89949B; font-size: 0.8rem; }
.footer a { color: #5a666d; text-decoration: none; }
.hidden { display: none; }
#toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast { display: flex; align-items: center; padding: 12px 18px; border-radius: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); font-weight: 500; font-size: 0.9rem; border: 2px solid #89949B; background: #fff; color: #3d474d; opacity: 0; transform: translateX(100%); animation: slideIn 0.5s forwards, fadeOut 0.5s 4.5s forwards; }
@keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
@keyframes fadeOut { from { opacity: 1; } to { opacity: 0; transform: translateX(100%); } }

/* Modal Styles */
.modal-overlay { 
  position: fixed; 
  top: 0; 
  left: 0; 
  width: 100%; 
  height: 100%; 
  background: rgba(0,0,0,0.5); 
  z-index: 1000; 
  display: none;  /* 默认隐藏 */
  align-items: center; 
  justify-content: center; 
  opacity: 0; 
  pointer-events: none; 
  transition: opacity 0.3s; 
}
.modal-overlay.open { 
  display: flex;  /* 打开时显示 */
  opacity: 1; 
  pointer-events: auto; 
}
.modal { 
  background: #fff; 
  width: 90%; 
  max-width: 600px; 
  max-height: 90vh; 
  overflow-y: auto; 
  border-radius: 8px; 
  padding: 25px; 
  box-shadow: 0 5px 15px rgba(0,0,0,0.3); 
  transform: translateY(-20px); 
  transition: transform 0.3s; 
}
.modal-overlay.open .modal { 
  transform: translateY(0); 
}
.modal-header { 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  margin-bottom: 15px; 
  border-bottom: 2px solid #E8EBED; 
  padding-bottom: 10px; 
}
.modal-title { 
  font-size: 1.25rem; 
  font-weight: bold; 
  color: #3d474d; 
}
.modal-close { 
  cursor: pointer; 
  font-size: 1.5rem; 
  color: #89949B; 
  line-height: 1; 
}
.modal-body { 
  text-align: left; 
}
.edit-field { 
  margin-bottom: 12px; 
}
.edit-field label { 
  font-size: 0.85rem; 
  color: #89949B; 
  margin-bottom: 4px; 
  display: block; 
}
.grid-2 { 
  display: grid; 
  grid-template-columns: 1fr 1fr; 
  gap: 10px; 
}
.grid-3 { 
  display: grid; 
  grid-template-columns: 1fr 1fr 1fr; 
  gap: 10px; 
}

/* Table & Modal Specific */
.table-container { overflow-x: auto; border: 2px solid #89949B; border-radius: 4px; background: #fff; margin-top:20px;}
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 2px solid #E8EBED; white-space: nowrap; }
th { font-weight: bold; color: #3d474d; background-color: #f0f2f5; }
.config-data-cell { white-space: normal; word-break: break-all; max-width: 200px; font-size: 0.8rem; color: #666; }
.domain-hosting-cell { font-size: 0.85rem; font-weight: 500; }

/* Domain Hosting Badges */
.hosting-badge { 
    display: inline-block; 
    padding: 2px 8px; 
    border-radius: 12px; 
    font-size: 0.75rem; 
    font-weight: 500; 
    line-height: 1.4;
}
.hosting-cloudflare { background: #e6f2ff; color: #0066cc; border: 1px solid #0066cc; }
.hosting-aliyun { background: #ffe6e6; color: #ff3300; border: 1px solid #ff3300; }
.hosting-tencent { background: #e6ffe6; color: #00aa00; border: 1px solid #00aa00; }
.hosting-aws { background: #fff2e6; color: #ff9900; border: 1px solid #ff9900; }
.hosting-gcore { background: #f0e6ff; color: #6622cc; border: 1px solid #6622cc; }
.hosting-fastly { background: #e6fffc; color: #008877; border: 1px solid #008877; }
.hosting-cachefly { background: #fff9e6; color: #cc8800; border: 1px solid #cc8800; }
.hosting-lightcdn { background: #e6f7ff; color: #0088cc; border: 1px solid #0088cc; }
.hosting-vercel { background: #000; color: #fff; border: 1px solid #000; }
.hosting-netlify { background: #00c7b7; color: #fff; border: 1px solid #00c7b7; }
.hosting-none { background: #f8f9fa; color: #6c757d; border: 1px solid #6c757d; }
.hosting-other { background: #f0f0f0; color: #666; border: 1px solid #666; }

/* Statistics & Charts */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
.stat-box { background: #f0f4f8; padding: 15px; border-radius: 4px; border-left: 4px solid #3b82f6; text-align: center; }
.stat-num { font-size: 1.8rem; color: #1e40af; font-weight: bold; display: block; }
.stat-label { font-size: 0.85rem; color: #4b5563; margin-top: 5px; }
.stat-sub { font-size: 0.75rem; color: #6b7280; margin-top: 3px; }
.chart-container { position: relative; width: 100%; height: 300px; margin: 20px 0; }
.user-info-panel { 
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
    color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; 
    display: flex; /* Changed to flex for better layout */
    flex-direction: column; 
    align-items: center; /* Center items horizontally */
    text-align: center;
}
.user-avatar { width: 64px; height: 64px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; margin: 0 auto 15px; color: #667eea; }
/* New styles for recent logs */
.access-log-container { 
  max-height: 300px; 
  overflow-y: auto; 
  border: 1px solid #E8EBED; 
  border-radius: 4px; 
  background: #fdfdfd; 
  padding: 10px;
}
.access-log-item { 
  display: flex; 
  flex-direction: column; 
  padding: 8px 0; 
  border-bottom: 1px solid #f0f2f5; 
  font-size: 0.85rem; 
  color: #3d474d; 
}
.access-log-item:last-child { 
  border-bottom: none; 
}
.timestamp { 
  font-weight: 500; 
  color: #5a666d; 
  margin-right: 10px; 
}
.log-type { 
  padding: 2px 6px; 
  border-radius: 3px; 
  font-size: 0.75rem; 
  font-weight: bold; 
  color: white; 
}
.type-subscription { background-color: #10b981; }
.type-apigen { background-color: #f59e0b; }
`;

// 登录页面 (不做修改)
const loginPageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>用户登录 - 配置管理器</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>

  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">用户登录</h1>
      <p class="profile-quote">登录以管理您的配置和订阅</p>
    
      <div class="card" style="max-width: 400px; margin: 0 auto;">
        <h2>登录账号</h2>
      
        <div class="form-group">
          <label>用户名</label>
          <input type="text" id="username" placeholder="请输入用户名" required>
        </div>
      
        <div class="form-group">
          <label>密码</label>
          <input type="password" id="password" placeholder="请输入密码" required>
        </div>
      
        <div class="info-box">
          <strong>温馨提示：</strong>
          <ul style="margin: 5px 0; padding-left: 15px;">
            <li>首次使用请先注册账号</li>
            <li>密码使用SHA-256加密存储</li>
            <li>登录后可使用所有管理功能</li>
          </ul>
        </div>
      
        <div style="display: flex; gap: 10px; margin-top: 20px;">
          <button class="nav-btn" onclick="window.location.href='/'">返回首页</button>
          <button class="nav-btn" onclick="window.location.href='/register.html'">注册账号</button>
          <button class="nav-btn primary" onclick="handleLogin()">登录</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = { success: '✅', error: '❌', info: 'ℹ️' };
  
    // 检查是否已登录
    window.addEventListener('DOMContentLoaded', () => {
      const token = localStorage.getItem('userToken');
      if (token) {
        fetch('/api/auth/user', {
          headers: { 'Authorization': 'Bearer ' + token }
        })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            window.location.href = '/';
          }
        });
      }
    });
  
    function showToast(m,t='info'){
      const c=document.getElementById('toast-container');
      const x=document.createElement('div');
      x.className='toast';
      x.innerHTML=\`<span>\${toastIcons[t]} \${m}</span>\`;
      c.appendChild(x);
      setTimeout(()=>x.remove(),4000);
    }
  
    async function handleLogin() {
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();
    
      if (!username || !password) {
        showToast('请填写用户名和密码', 'error');
        return;
      }
    
      const button = document.querySelector('.nav-btn.primary');
      const originalText = button.innerHTML;
      button.innerHTML = '登录中...';
      button.disabled = true;
    
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
      
        const data = await response.json();
      
        if (data.success) {
          localStorage.setItem('userToken', data.token);
          localStorage.setItem('username', data.user.username);
          localStorage.setItem('userId', data.user.id);
          localStorage.setItem('userUuid', data.user.uuid); // 存储用户 userUuid
        
          showToast('登录成功！正在跳转...', 'success');
          setTimeout(() => {
            window.location.href = '/';
          }, 1000);
        } else {
          showToast(data.error || '登录失败', 'error');
        }
      } catch (error) {
        showToast('网络错误: ' + error.message, 'error');
      } finally {
        button.innerHTML = originalText;
        button.disabled = false;
      }
    }
  
    document.getElementById('password').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        handleLogin();
      }
    });
  </script>
</body>
</html>
`;

// 注册页面 (不做修改)
const registerPageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>用户注册 - 配置管理器</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>

  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">用户注册</h1>
      <p class="profile-quote">创建新账号以使用完整功能</p>
    
      <div class="card" style="max-width: 400px; margin: 0 auto;">
        <h2>注册账号</h2>
      
        <div class="form-group">
          <label>用户名 *</label>
          <input type="text" id="username" placeholder="3-20个字符" required>
          <small style="color: #89949B; display: block; margin-top: 4px;">用户名将用于登录和显示</small>
        </div>
      
        <div class="form-group">
          <label>邮箱 (可选)</label>
          <input type="email" id="email" placeholder="example@domain.com">
          <small style="color: #89949B; display: block; margin-top: 4px;">可用于找回密码</small>
        </div>
      
        <div class="form-group">
          <label>密码 *</label>
          <input type="password" id="password" placeholder="至少6个字符" required>
        </div>
      
        <div class="form-group">
          <label>确认密码 *</label>
          <input type="password" id="confirmPassword" placeholder="再次输入密码" required>
        </div>
      
        <div class="info-box">
          <strong>注册须知：</strong>
          <ul style="margin: 5px 0; padding-left: 15px;">
            <li>注册后可创建和管理自己的UUID</li>
            <li>支持配置的增删改查功能</li>
            <li>可查看详细的访问统计信息</li>
            <li>密码使用SHA-256加密存储</li>
          </ul>
        </div>
      
        <div style="display: flex; gap: 10px; margin-top: 20px;">
          <button class="nav-btn" onclick="window.location.href='/'">返回首页</button>
          <button class="nav-btn" onclick="window.location.href='/login.html'">已有账号</button>
          <button class="nav-btn primary" onclick="handleRegister()">注册</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = { success: '✅', error: '❌', info: 'ℹ️' };
  
    function showToast(m,t='info'){
      const c=document.getElementById('toast-container');
      const x=document.createElement('div');
      x.className='toast';
      x.innerHTML=\`<span>\${toastIcons[t]} \${m}</span>\`;
      c.appendChild(x);
      setTimeout(()=>x.remove(),4000);
    }
  
    async function handleRegister() {
      const username = document.getElementById('username').value.trim();
      const email = document.getElementById('email').value.trim() || null;
      const password = document.getElementById('password').value.trim();
      const confirmPassword = document.getElementById('confirmPassword').value.trim();
    
      if (!username) {
        showToast('请输入用户名', 'error');
        return;
      }
    
      if (username.length < 3 || username.length > 20) {
        showToast('用户名长度必须为3-20个字符', 'error');
        return;
      }
    
      if (!password) {
        showToast('请输入密码', 'error');
        return;
      }
    
      if (password.length < 6) {
        showToast('密码长度至少6个字符', 'error');
        return;
      }
    
      if (password !== confirmPassword) {
        showToast('两次输入的密码不一致', 'error');
        return;
      }
    
      if (email && !/^[^\s@]+@[^\s@]+\\.[^\s@]+$/.test(email)) {
        showToast('邮箱格式不正确', 'error');
        return;
      }
    
      const button = document.querySelector('.nav-btn.primary');
      const originalText = button.innerHTML;
      button.innerHTML = '注册中...';
      button.disabled = true;
    
      try {
        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password })
        });
      
        const data = await response.json();
      
        if (data.success) {
          localStorage.setItem('userToken', data.token);
          localStorage.setItem('username', data.user.username);
          localStorage.setItem('userId', data.user.id);
          localStorage.setItem('userUuid', data.user.uuid); // 存储用户 userUuid
        
          showToast('注册成功！自动登录中...', 'success');
          setTimeout(() => {
            window.location.href = '/';
          }, 1500);
        } else {
          showToast(data.error || '注册失败', 'error');
        }
      } catch (error) {
        showToast('网络错误: ' + error.message, 'error');
      } finally {
        button.innerHTML = originalText;
        button.disabled = false;
      }
    }
  
    document.getElementById('confirmPassword').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        handleRegister();
      }
    });
  </script>
</body>
</html>
`;

// 主管理页面（修正版）
const managePageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
  <title>配置管理器 - 用户中心</title>
  <style>${newGlobalStyle}</style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div id="toast-container"></div>

  <!-- Edit Modal -->
  <div id="editModalOverlay" class="modal-overlay">
    <div class="modal">
      <div class="modal-header">
        <span class="modal-title">编辑配置 (Editor)</span>
        <span class="modal-close" onclick="closeEditModal()">&times;</span>
      </div>
      <div class="modal-body">
        <input type="hidden" id="edit-id">
        <input type="hidden" id="edit-protocol">
        <div class="grid-3">
            <div class="edit-field">
              <label>别名 (Remarks)</label>
              <input type="text" id="edit-ps">
            </div>
            <div class="edit-field">
              <label>端口 (Port)</label>
              <input type="number" id="edit-port">
            </div>
            <div class="edit-field">
              <label>域名托管 (Hosting)</label>
              <select id="edit-domain-hosting" class="hosting-select">
                <option value="Cloudflare">Cloudflare</option>
                <option value="阿里ESA">阿里ESA</option>
                <option value="腾讯Edgeone">腾讯Edgeone</option>
                <option value="AWS Cloudfront">AWS Cloudfront</option>
                <option value="Gcore">Gcore</option>
                <option value="Fastly">Fastly</option>
                <option value="CacheFly">CacheFly</option>
                <option value="LightCDN">LightCDN</option>
                <option value="Vercel">Vercel</option>
                <option value="Netlify">Netlify</option>
                <option value="无">无</option>
                <option value="其他">其他</option>
              </select>
            </div>
        </div>
        <div class="edit-field">
          <label>地址 (Address)</label>
          <input type="text" id="edit-add">
        </div>
        <div class="edit-field">
          <label>UUID / Password</label>
          <input type="text" id="edit-id-uuid">
        </div>
        <div class="grid-2">
          <div class="edit-field">
            <label>传输 (Net)</label>
            <select id="edit-net">
              <option value="tcp">TCP</option>
              <option value="ws">WebSocket</option>
              <option value="grpc">gRPC</option>
            </select>
          </div>
          <div class="edit-field">
            <label>伪装 (Type)</label>
            <input type="text" id="edit-type" placeholder="none">
          </div>
        </div>
        <div class="grid-2">
          <div class="edit-field">
            <label>伪装域名 (Host)</label>
            <input type="text" id="edit-host">
          </div>
          <div class="edit-field">
            <label>路径 (Path)</label>
            <input type="text" id="edit-path">
          </div>
        </div>
        <div class="grid-2">
          <div class="edit-field">
            <label>TLS</label>
            <select id="edit-tls">
              <option value="">关闭</option>
              <option value="tls">开启 TLS</option>
            </select>
          </div>
          <div class="edit-field">
            <label>SNI</label>
            <input type="text" id="edit-sni">
          </div>
        </div>
        <div style="margin-top: 20px; text-align: right;">
          <button class="nav-btn" onclick="closeEditModal()">取消</button>
          <button class="nav-btn primary" onclick="saveEditedConfig()">保存修改</button>
        </div>
      </div>
    </div>
  </div>

  <!-- New Header for Logo and Auth Controls -->
  <header class="app-header">
      <div class="logo">配置管理器</div>
      <div class="auth-controls">
          <!-- Login button (visible when not logged in) -->
          <button id="loginBtn" class="nav-btn" onclick="window.location.href='/login.html'">登录/注册</button>
          <!-- User Info display (visible when logged in) -->
          <div id="userInfoPanelHeader" class="user-info-panel-header" style="display: none;">
              <div class="user-avatar" id="userAvatarHeader"></div>
              <span id="loggedInUsernameHeader" style="margin-left: 10px; color: #5a666d; font-weight: bold;"></span>
              <div class="nav-grid-header">
                  <button class="nav-btn" onclick="showUserDashboard()">用户面板</button>
                  <button class="nav-btn primary" onclick="handleLogout()">退出登录</button>
              </div>
          </div>
      </div>
  </header>

  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">V2Ray / Clash 配置管理中心</h1>
      <p id="profile-quote" class="profile-quote">节点存储与订阅管理</p>
    
      <!-- Action Buttons in main content area -->
      <div class="nav-grid">
        <button id="allConfigsOverviewBtn" class="nav-btn" onclick="loadUserAggregatedData()" style="display: none;">所有Config UUID总览</button>
        <button id="manageBtn" class="nav-btn" onclick="showSingleConfigMode()" style="display: none;">单个Config管理</button>
        <a href="https://cfst.api.yangzifun.org" target="_blank" class="nav-btn primary">配置生成</a>
      </div>

      <!-- UUID Management -->
      <div class="card">
        <h2>Config UUID 管理</h2>
        <div id="uuidMgmtArea">
          <div class="form-group" style="display:grid; grid-template-columns: 1fr auto; gap:10px; align-items:center;">
            <input type="text" id="queryUuidInput" placeholder="输入或选择Config UUID进行管理" disabled>
            <button id="queryBtn" class="nav-btn primary" onclick="manageQueryByUuid()" disabled>查询/管理</button>
          </div>
        
          <div class="form-group" style="display:grid; grid-template-columns: 1fr auto; gap:10px; align-items:center; margin-top: 15px; padding-top: 15px; border-top: 1px dashed #E8EBED;">
              <input type="text" id="linkUuidInput" placeholder="输入已有Config UUID进行关联" disabled>
              <button id="linkUuidBtn" class="nav-btn" onclick="handleLinkUuid()" disabled>关联 UUID</button>
          </div>

          <div id="userUuidsList" class="hidden" style="margin-top: 15px; border-top: 1px dashed #e8ebed; padding-top: 15px;">
            <h3 style="font-size: 1rem; margin: 0 0 10px 0; color: #5a666d;">我的已关联 Config UUID 列表</h3>
            <div id="uuidsContainer" style="display: flex; flex-wrap: wrap; gap: 8px; max-height: 150px; overflow-y: auto; padding: 10px; background: #f0f2f5; border-radius: 4px;">
              <div style="color: #89949B; width: 100%; text-align: center;">加载中...</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Result Display -->
      <div id="resultCard" class="card hidden">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
          <h2 style="margin: 0;" id="resultCardTitle">配置列表</h2>
          <div>
            <button class="nav-btn" onclick="generateNewUuid()" id="generateNewUuidBtn" disabled>生成新Config UUID</button>
            <button class="nav-btn" style="background:#d44; color:#fff; border-color:#d44;" onclick="deleteAll()" id="deleteAllBtn" disabled>删除当前组所有</button>
          </div>
        </div>
        <div id="queryResultsContainer"></div>
      </div>

      <!-- Statistics -->
      <div id="statsCard" class="card hidden">
        <h2 id="statsCardTitle">访问统计</h2>
        <div class="chart-controls">
          <select id="statsDays" onchange="loadUuidStats()">
            <option value="7">最近7天</option>
            <option value="14">最近14天</option>
            <option value="30" selected>最近30天</option>
            <option value="60">最近60天</option>
          </select>
          <button class="nav-btn" onclick="loadUuidStats()">刷新</button>
          <button class="nav-btn" onclick="switchChartType('total')" id="chartTotalBtn">总访问</button>
          <button class="nav-btn" onclick="switchChartType('split')" id="chartSplitBtn">分类统计</button>
        </div>
      
        <div id="statsSummary" class="stat-grid">
          <div style="text-align: center; padding: 20px; color: #6b7280;">加载统计数据...</div>
        </div>
      
        <div class="chart-container">
          <canvas id="statsChart"></canvas>
        </div>
      
        <div style="margin-top: 20px;">
          <h3 style="font-size: 1.1rem; margin: 0 0 10px 0;">最近访问记录</h3>
          <div id="recentLogs" class="access-log-container">
            <div style="text-align: center; padding: 20px; color: #6b7280;">加载中...</div>
          </div>
        </div>
      </div>

      <!-- Add Config -->
      <div id="addCard" class="card hidden">
        <h2 id="addCardTitle">添加新节点</h2>
        <div class="form-group">
          <label>域名托管服务 (Domain Hosting)</label>
          <select id="domainHostingSelect" class="hosting-select">
            <option value="Cloudflare" selected>Cloudflare</option>
            <option value="阿里ESA">阿里ESA</option>
            <option value="腾讯Edgeone">腾讯Edgeone</option>
            <option value="AWS Cloudfront">AWS Cloudfront</option>
            <option value="Gcore">Gcore</option>
            <option value="Fastly">Fastly</option>
            <option value="CacheFly">CacheFly</option>
            <option value="LightCDN">LightCDN</option>
            <option value="Vercel">Vercel</option>
            <option value="Netlify">Netlify</option>
            <option value="无">无</option>
            <option value="其他">其他</option>
          </select>
          <div class="info-box">
            <strong>说明：</strong> 选择此配置使用的域名托管服务。
          </div>
        </div>
        <div class="form-group">
          <label>配置数据 (可批量添加)</label>
          <textarea id="addConfigData" placeholder="支持批量添加：
vmess://...
vless://...
trojan://..." rows="4"></textarea>
        </div>
        <button onclick="manageAddConfig()" class="nav-btn primary" style="width:100%" disabled>添加到当前 UUID</button>
      </div>

      <!-- User Dashboard -->
      <div id="userDashboard" class="card hidden">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
          <h2 style="margin: 0;">用户仪表板</h2>
          <button class="nav-btn" onclick="hideUserDashboard()">返回管理</button>
        </div>
      
        <div id="userStats" class="stat-grid">
          <div class="stat-box">
            <span class="stat-num" id="userConfigCount">0</span>
            <span class="stat-label">配置总数</span>
          </div>
          <div class="stat-box">
            <span class="stat-num" id="userUuidCount">0</span>
            <span class="stat-label">Config UUID组数</span>
          </div>
          <div class="stat-box">
            <span class="stat-num" id="userAccessCount">0</span>
            <span class="stat-label">总访问量</span>
          </div>
          <div class="stat-box">
            <span class="stat-num" id="userProtocols">0</span>
            <span class="stat-label">协议类型</span>
          </div>
        </div>
      
        <h3 style="margin: 30px 0 15px 0;">我的 Config UUID 列表</h3>
        <div id="dashboardUuids" style="display: flex; flex-wrap: wrap; gap: 8px; padding: 15px; background: #f0f2f5; border-radius: 4px; max-height: 200px; overflow-y: auto;">
          <div style="text-align: center; width: 100%; color: #89949B;">加载中...</div>
        </div>
      </div>

      <footer class="footer">
        <p>Powered by <a href="https://www.yangzihome.space">YZFN</a> | <a href="https://www.yangzihome.space/security.html">安全声明</a></p>
        <p id="versionInfo" style="font-size: 0.7rem; margin-top: 5px;">用户系统 v1.0.3</p>
      </footer>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = { success: '✅', error: '❌', info: 'ℹ️' };
    let currentUuid = ''; // The Config UUID currently selected for management. Can be '_all_' for overview.
    let currentViewMode = 'overview'; // 'overview' or 'single'
    let statsChart = null;
    let currentChartType = 'split'; // For stats chart: 'total' or 'split'
    let userToken = localStorage.getItem('userToken');
    let userInfo = null; // Store complete user data, including userUuid

    // Domain hosting styles mapping
    const hostingStyleMap = {
      'Cloudflare': 'hosting-cloudflare', '阿里ESA': 'hosting-aliyun',
      '腾讯Edgeone': 'hosting-tencent', 'AWS Cloudfront': 'hosting-aws',
      'Gcore': 'hosting-gcore', 'Fastly': 'hosting-fastly',
      'CacheFly': 'hosting-cachefly', 'LightCDN': 'hosting-lightcdn',
      'Vercel': 'hosting-vercel', 'Netlify': 'hosting-netlify',
      '无': 'hosting-none', '其他': 'hosting-other'
    };
  
    // --- Initial Setup ---
    document.addEventListener('DOMContentLoaded', async () => {
        // Initially hide management cards and user dashboard
        document.getElementById('resultCard').classList.add('hidden');
        document.getElementById('statsCard').classList.add('hidden');
        document.getElementById('addCard').classList.add('hidden');
        document.getElementById('userDashboard').classList.add('hidden');
        
        await checkLoginStatus(); // Determine UI state based on login
        initEventListeners();
        updateChartButtons(); // Set initial chart buttons state
    });
  
    // --- Utility Functions ---
    function showToast(m,t='info'){
      const c=document.getElementById('toast-container');
      const x=document.createElement('div');
      x.className='toast';
      x.innerHTML=\`<span>\${toastIcons[t]} \${m}</span>\`;
      c.appendChild(x);
      setTimeout(()=>x.remove(),4000);
    }
  
    function setButtonLoading(b,l){
      if(l){
        b.dataset.originalText = b.innerHTML;
        b.disabled=true;
        b.innerHTML='...';
      }else{
        b.disabled=false;
        if(b.dataset.originalText) b.innerHTML=b.dataset.originalText;
      }
    }
  
    function initEventListeners() {
      const queryInput = document.getElementById('queryUuidInput');
      queryInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') { manageQueryByUuid(); } });
      
      const linkInput = document.getElementById('linkUuidInput');
      linkInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') { handleLinkUuid(); } });
      linkInput.addEventListener('input', linkUuidBtnInitialState); // Enable/disable link button on input
    }

    function b64DecodeUnicode(str) { 
      try { // Added try-catch for robustness
          return decodeURIComponent(atob(str).split('').map(c=>'%'+('00'+c.charCodeAt(0).toString(16)).slice(-2)).join('')); 
      } catch (e) {
          console.error("Base64 Decode Error:", e);
          return '';
      }
    }
  
    function b64EncodeUnicode(str) { 
      return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,(m,p1)=>String.fromCharCode(parseInt(p1,16)))); 
    }

    function formatDate(dateStr) {
      if (!dateStr) return '';
      const date = new Date(dateStr);
      const month = (date.getMonth() + 1).toString().padStart(2, '0');
      const day = date.getDate().toString().padStart(2, '0');
      return \`\${month}/\${day}\`;
    }
  
    function formatDateTime(dateStr) {
      if (!dateStr) return '';
      const date = new Date(dateStr);
      const year = date.getFullYear();
      const month = (date.getMonth() + 1).toString().padStart(2, '0');
      const day = date.getDate().toString().padStart(2, '0');
      const hours = date.getHours().toString().padStart(2, '0');
      const minutes = date.getMinutes().toString().padStart(2, '0');
      return \`\${year}-\${month}-\${day} \${hours}:\${minutes}\`;
    }
  
    // --- User Authentication & UI Management ---
  
    async function checkLoginStatus() {
      userToken = localStorage.getItem('userToken');
      if (!userToken) {
        updateUIForGuest();
        return;
      }
    
      try {
        const response = await fetch('/api/auth/user', {
          headers: { 'Authorization': 'Bearer ' + userToken }
        });
      
        const data = await response.json();
      
        if (data.success) {
          userInfo = data; // Store complete user info
          localStorage.setItem('username', userInfo.user.username);
          localStorage.setItem('userId', userInfo.user.id);
          localStorage.setItem('userUuid', userInfo.user.uuid); // Ensure user's own UUID is stored
          updateUIForUser();
          await loadUserUuids(); // Await so that total overview can use fresh UUID list
          await loadUserAggregatedData(); // Load all configs and stats overview by default
        } else {
          // Token invalid or expired
          clearUserLocalStorage();
          userToken = null;
          userInfo = null;
          updateUIForGuest();
        }
      } catch (error) {
        showToast('检查登录状态失败，请重试', 'error');
        clearUserLocalStorage();
        userToken = null;
        userInfo = null;
        updateUIForGuest();
      }
    }
  
    function clearUserLocalStorage() {
      localStorage.removeItem('userToken');
      localStorage.removeItem('username');
      localStorage.removeItem('userId');
      localStorage.removeItem('userUuid');
    }
  
    function updateUIForUser() {
      document.getElementById('profile-quote').textContent = 
        \`欢迎回来，\${userInfo.user.username}！您有 \${userInfo.stats.configs.total || 0} 个配置\`;
    
      document.getElementById('loginBtn').style.display = 'none'; // Hide login button
      document.getElementById('userInfoPanelHeader').style.display = 'flex'; // Show user info in header
      document.getElementById('loggedInUsernameHeader').textContent = userInfo.user.username;
      document.getElementById('userAvatarHeader').textContent = userInfo.user.username.charAt(0).toUpperCase();
    
      document.getElementById('dashboardBtn').style.display = 'inline-flex';
      document.getElementById('allConfigsOverviewBtn').style.display = 'inline-flex';
      document.getElementById('manageBtn').style.display = 'inline-flex';
      document.getElementById('userUuidsList').classList.remove('hidden'); 
    
      // Enable buttons that require login
      document.getElementById('queryBtn').disabled = false;
      document.getElementById('linkUuidInput').disabled = false;
      linkUuidBtnInitialState(); // Set initial state of linkUuidBtn

      document.getElementById('queryUuidInput').disabled = false;
    }
  
    function updateUIForGuest() {
      document.getElementById('profile-quote').textContent = '节点存储与订阅管理 (请登录使用完整功能)';
    
      document.getElementById('loginBtn').style.display = 'inline-flex'; // Show login button
      document.getElementById('userInfoPanelHeader').style.display = 'none'; // Hide user info in header
      
      document.getElementById('dashboardBtn').style.display = 'none';
      document.getElementById('allConfigsOverviewBtn').style.display = 'none';
      document.getElementById('manageBtn').style.display = 'none';
      document.getElementById('userUuidsList').classList.add('hidden'); 
    
      // Disable buttons that require login
      document.getElementById('queryBtn').disabled = true;
      document.getElementById('linkUuidInput').disabled = true;
      document.getElementById('linkUuidBtn').disabled = true;
      document.getElementById('generateNewUuidBtn').disabled = true;
      document.getElementById('deleteAllBtn').disabled = true;
      document.querySelector('#addCard .nav-btn.primary').disabled = true; 
      
      document.getElementById('queryUuidInput').value = '';
      document.getElementById('queryUuidInput').disabled = true; // Disable query input for guests
      document.getElementById('linkUuidInput').value = '';
      
      // Clear management results and stats displays
      document.getElementById('queryResultsContainer').innerHTML = '';
      document.getElementById('statsSummary').innerHTML = '';
      document.getElementById('recentLogs').innerHTML = '';
      document.getElementById('uuidsContainer').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">请登录以查看我的Config UUID</div>';
      document.getElementById('dashboardUuids').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">请登录以查看我的Config UUID</div>';
      document.getElementById('resultCardTitle').textContent = '配置列表';
      document.getElementById('statsCardTitle').textContent = '访问统计';
      document.getElementById('addCardTitle').textContent = '添加新节点';
    
      document.getElementById('resultCard').classList.add('hidden');
      document.getElementById('statsCard').classList.add('hidden');
      document.getElementById('addCard').classList.add('hidden');
      document.getElementById('userDashboard').classList.add('hidden');
    
      if (statsChart) { statsChart.destroy(); statsChart = null; }
      currentUuid = '';
      currentViewMode = 'overview';
    }
  
    async function handleLogout() {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + userToken }
        });
      } catch (error) {
        // Ignore logout errors, proceed with client-side cleanup
      }
    
      clearUserLocalStorage();
      userToken = null;
      userInfo = null;
    
      showToast('已退出登录', 'success');
      setTimeout(() => {
        window.location.href = '/'; // Reload the page to reset UI
      }, 500);
    }

    // Controls the disabled state of the 'linkUuidBtn' based on login status and input field content
    function linkUuidBtnInitialState() {
        const linkInput = document.getElementById('linkUuidInput');
        const linkBtn = document.getElementById('linkUuidBtn');
        if (linkInput && linkBtn) {
            linkBtn.disabled = !userToken || linkInput.value.trim().length === 0;
        }
    }


    // --- New/Modified Config UUID Management ---

    // 处理关联 Config UUID
    async function handleLinkUuid() {
        const configUuidToLink = document.getElementById('linkUuidInput').value.trim();
        if (!configUuidToLink) {
            showToast('请输入要关联的 Config UUID', 'error');
            return;
        }
        if (!userToken) {
            showToast('请登录以关联 Config UUID', 'error');
            return;
        }

        const button = document.getElementById('linkUuidBtn');
        setButtonLoading(button, true);

        try {
            const response = await fetch('/api/user/link-config-uuid', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + userToken },
                body: JSON.stringify({ configUuid: configUuidToLink })
            });

            const data = await response.json();
            if (response.status === 401) {
                showToast('会话已过期，请重新登录', 'error');
                clearUserLocalStorage(); updateUIForGuest(); return;
            } else if (data.success || response.status === 200) { // status 200 for "already owned"
                showToast(data.message, 'success');
                document.getElementById('linkUuidInput').value = '';
                await loadUserUuids(); // Refresh the list of owned UUIDs
                await loadUserAggregatedData(); // Update overview data
            } else {
                showToast(data.error || data.message || '关联失败', 'error');
            }
        } catch (error) {
            showToast('网络错误: ' + error.message, 'error');
        } finally {
            setButtonLoading(button, false);
            linkUuidBtnInitialState(); // Reset button state after operation
        }
    }

    // 加载用户拥有的所有Config UUID列表
    async function loadUserUuids() {
      if (!userToken) { 
        document.getElementById('uuidsContainer').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">请登录以查看我的Config UUID</div>';
        document.getElementById('dashboardUuids').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">请登录以查看我的Config UUID</div>';
        return;
      }
    
      try {
        const response = await fetch('/api/user/uuids', {
          headers: { 'Authorization': 'Bearer ' + userToken }
        });
      
        const data = await response.json();
        if (data.success) {
          displayUserUuids(data.uuids);
        } else {
          document.getElementById('uuidsContainer').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">暂无Config UUID，请先添加或关联</div>';
          document.getElementById('dashboardUuids').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">暂无Config UUID</div>';
        }
      } catch (error) {
        document.getElementById('uuidsContainer').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">加载失败</div>';
        document.getElementById('dashboardUuids').innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">加载失败</div>';
        showToast('加载我的Config UUID列表失败', 'error');
      }
    }
  
    // 显示用户Config UUID列表到UI
    function displayUserUuids(uuids) {
      const container = document.getElementById('uuidsContainer');
      const dashboardContainer = document.getElementById('dashboardUuids');
    
      if (!uuids || uuids.length === 0) {
        container.innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">暂无Config UUID，请先添加或关联</div>';
        dashboardContainer.innerHTML = '<div style="color: #89949B; width: 100%; text-align: center;">暂无Config UUID</div>';
        return;
      }
    
      let html = '';
      uuids.forEach(uuid => {
        const shortUuid = uuid.substring(0, 8) + '...';
        html += \`
          <button class="nav-btn" style="font-size: 0.85rem; padding: 6px 12px; min-width: 80px;" 
                  onclick="loadUuid('\${uuid}')" title="\${uuid}">
            \${shortUuid}
          </button>
        \`;
      });
    
      container.innerHTML = html;
      dashboardContainer.innerHTML = html;
    }
  
    // 从列表或输入框加载并管理单个Config UUID
    async function loadUuid(uuid) {
      if (!userToken) { showToast('请登录以管理Config UUID', 'error'); return; }

      currentViewMode = 'single';
      currentUuid = uuid;
      document.getElementById('queryUuidInput').value = uuid;
      // Visually activate "single UUID manage" button
      document.getElementById('allConfigsOverviewBtn').classList.remove('active');
      document.getElementById('manageBtn').classList.add('active');
      
      // Enable single UUID management buttons
      document.getElementById('generateNewUuidBtn').disabled = false;
      document.getElementById('deleteAllBtn').disabled = false; 
      document.querySelector('#addCard .nav-btn.primary').disabled = false;
      
      await manageQueryByUuid(); // Now manageQueryByUuid will use currentUuid and render for single
      hideUserDashboard(); // Hide dashboard if it was open
    }
  
    // 加载所有用户Config UUID的概览数据和统计
    async function loadUserAggregatedData() {
        if (!userToken) { showToast('请登录以查看总览数据', 'error'); return; }

        currentViewMode = 'overview';
        currentUuid = '_all_';
        document.getElementById('queryUuidInput').value = ''; // Clear input for overview
        // Visually activate "all configs overview" button
        document.getElementById('allConfigsOverviewBtn').classList.add('active');
        document.getElementById('manageBtn').classList.remove('active');

        // Update card titles for overview
        document.getElementById('resultCardTitle').textContent = '所有Config UUID 配置列表总览';
        document.getElementById('statsCardTitle').textContent = '所有Config UUID 访问统计总览';
        document.getElementById('addCardTitle').textContent = '请选中单个 Config UUID 后再添加';

        // Disable management buttons in overview mode
        document.getElementById('generateNewUuidBtn').disabled = true;
        document.getElementById('deleteAllBtn').disabled = true;
        document.querySelector('#addCard .nav-btn.primary').disabled = true;

        // Show management cards
        document.getElementById('resultCard').classList.remove('hidden');
        document.getElementById('statsCard').classList.remove('hidden');
        document.getElementById('addCard').classList.remove('hidden');
        
        hideUserDashboard(); // Always ensure dashboard is hidden when managing configs
        await manageQueryByUuid(); // Loads config list for _all_
        await loadUuidStats();    // Loads stats for _all_
        showToast('已加载所有Config UUID总览数据', 'info');
    }

    // Function to switch to single config mode by prompting user or using current input
    async function showSingleConfigMode() {
        if (!userToken) { showToast('请登录以管理单个Config UUID', 'error'); return; }

        if (currentViewMode === 'single' && currentUuid && currentUuid !== '_all_') {
            // Already in single mode with a UUID, just ensure UI is correct
            await loadUuid(currentUuid);
            return;
        }

        const inputUuid = document.getElementById('queryUuidInput').value.trim();
        if (inputUuid) {
            await loadUuid(inputUuid);
        } else {
            showToast('请在上方输入框中输入或从列表中选择一个Config UUID', 'info');
            // Ensure UI is set for single mode, but with no active UUID selected
            currentViewMode = 'single';
            currentUuid = ''; // No current UUID selected
            document.getElementById('allConfigsOverviewBtn').classList.remove('active');
            document.getElementById('manageBtn').classList.add('active');

            // Reset management area to empty/prompt
            document.getElementById('queryResultsContainer').innerHTML = '<p style="padding:20px;text-align:center;color:#89949B">请在上方输入框中输入或从列表中选择一个Config UUID。</p>';
            document.getElementById('statsSummary').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无统计数据 (等待选择)</div>';
            document.getElementById('recentLogs').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无访问记录 (等待选择)</div>';
            if (statsChart) { statsChart.destroy(); statsChart = null; }
            document.getElementById('resultCardTitle').textContent = '配置列表 (未选中)';
            document.getElementById('statsCardTitle').textContent = '访问统计 (未选中)';
            document.getElementById('addCardTitle').textContent = '请选中单个 Config UUID 后再添加';

            // Buttons disabled until a UUID is chosen
            document.getElementById('generateNewUuidBtn').disabled = false; // Allow generation of new one
            document.getElementById('deleteAllBtn').disabled = true;
            document.querySelector('#addCard .nav-btn.primary').disabled = true;
            
            document.getElementById('resultCard').classList.remove('hidden');
            document.getElementById('statsCard').classList.remove('hidden');
            document.getElementById('addCard').classList.remove('hidden');
            hideUserDashboard(); // Hide dashboard if it was open
        }
    }


    // 生成新的配置UUID（仅用于填充输入框，不是用户userUuid），并切换到单UUID模式
    function generateNewUuid() {
      if (!userToken) { showToast('请登录以生成新的Config UUID', 'error'); return; }

      const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
      document.getElementById('queryUuidInput').value = uuid;
      showToast('已生成新的Config UUID到输入框', 'info');
      
      // Auto-switch to single UUID mode for the newly generated UUID
      currentViewMode = 'single';
      currentUuid = uuid;
      document.getElementById('allConfigsOverviewBtn').classList.remove('active');
      document.getElementById('manageBtn').classList.add('active');

      // Clear current display while preparing for new UUID
      document.getElementById('queryResultsContainer').innerHTML = '<p style="padding:20px;text-align:center;color:#89949B">请添加配置到这个新的Config UUID。</p>';
      document.getElementById('statsSummary').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无统计数据 (新Config UUID)</div>';
      document.getElementById('recentLogs').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无访问记录 (新Config UUID)</div>';
      if (statsChart) { statsChart.destroy(); statsChart = null; }
      
      // Update card titles
      document.getElementById('resultCardTitle').textContent = \`配置列表 (\${uuid.substring(0,8)}...)\`;
      document.getElementById('statsCardTitle').textContent = \`访问统计 (\${uuid.substring(0,8)}...)\`;
      document.getElementById('addCardTitle').textContent = \`添加到当前Config UUID (\${uuid.substring(0,8)}...)\`;

      // Enable management buttons for this single UUID
      document.getElementById('generateNewUuidBtn').disabled = false;
      document.getElementById('deleteAllBtn').disabled = true; // No configs yet, disable delete
      document.querySelector('#addCard .nav-btn.primary').disabled = false;
      
      document.getElementById('resultCard').classList.remove('hidden');
      document.getElementById('statsCard').classList.remove('hidden');
      document.getElementById('addCard').classList.remove('hidden');
      hideUserDashboard();
    }
  
    // --- Main Management Actions ---
  
    async function manageQueryByUuid(){
      const uuidToQuery = currentUuid; // Use global state
      const isOverview = uuidToQuery === '_all_';
      const b = document.getElementById('queryBtn'); 
      setButtonLoading(b, true);
    
      if(!uuidToQuery && !isOverview){ 
        showToast('请选择或输入1个Config UUID','error'); 
        setButtonLoading(b, false); 
        return;
      }
      if (!userToken) { // Double-check authorization on client-side
          showToast('请登录以管理配置', 'error');
          setButtonLoading(b, false);
          return;
      }
    
      // Update card titles dynamically
      if (isOverview) {
          document.getElementById('resultCardTitle').textContent = '所有Config UUID 配置列表总览';
          document.getElementById('statsCardTitle').textContent = '所有Config UUID 访问统计总览';
          document.getElementById('addCardTitle').textContent = '请选中单个 Config UUID 后再添加';
      } else {
          document.getElementById('resultCardTitle').textContent = \`配置列表 (\${uuidToQuery.substring(0,8)}...)\`;
          document.getElementById('statsCardTitle').textContent = \`访问统计 (\${uuidToQuery.substring(0,8)}...)\`;
          document.getElementById('addCardTitle').textContent = \`添加到当前Config UUID (\${uuidToQuery.substring(0,8)}...)\`;
      }

      hideUserDashboard();
    
      try {
        const headers = { 'Authorization': 'Bearer ' + userToken };
        const configResponse = await fetch(\`/manage/configs/\${uuidToQuery}\`, { headers });
        const c = document.getElementById('queryResultsContainer');
      
        if (configResponse.status === 401) { 
            c.innerHTML = '<p style="padding:20px;text-align:center;color:#89949B">未登录或会话已过期，请重新登录。</p>';
            document.getElementById('deleteAllBtn').disabled = true;
            clearUserLocalStorage(); updateUIForGuest(); showToast('会话已过期，请重新登录', 'error'); return;
        }
        if (configResponse.status === 403) { 
            c.innerHTML = '<p style="padding:20px;text-align:center;color:#89949B">您无权管理此Config UUID。</p>';
            document.getElementById('deleteAllBtn').disabled = true;
        } else if (configResponse.status === 404) { 
            c.innerHTML = '<p style="padding:20px;text-align:center;color:#89949B'>未找到任何配置，可以开始添加。</p>';
            document.getElementById('deleteAllBtn').disabled = true;
            if (currentViewMode === 'single') document.querySelector('#addCard .nav-btn.primary').disabled = false;
        } else {
            const d = await configResponse.json();
            if (!d.configs || d.configs.length === 0) {
              c.innerHTML = '<p style="padding:20px;text-align:center;color:#89949B'>未找到任何配置，可以开始添加。</p>';
              document.getElementById('deleteAllBtn').disabled = true;
              if (currentViewMode === 'single') document.querySelector('#addCard .nav-btn.primary').disabled = false;
            } else {
              let h = '<div class="table-container"><table><thead><tr>';
              if (isOverview) h += '<th>Config UUID</th>'; // Add UUID column for overview
              h += '<th>备注</th><th>协议</th><th>域名托管</th><th>配置</th><th>操作</th></tr></thead><tbody>';
              d.configs.forEach(Row => {
                const sc = JSON.stringify(Row).replace(/"/g, '&quot;');
                const hosting = Row.domain_hosting || 'Cloudflare';
                const hostingClass = hostingStyleMap[hosting] || 'hosting-other';
                h += \`
                  <tr>
                    \${isOverview ? \`<td><button class="nav-btn" style="font-size:0.8em; padding: 4px 8px; min-width:unset;" onclick="loadUuid('\${Row.uuid}')" title="\${Row.uuid}">\${Row.uuid.substring(0, 8)}...</button></td>\` : ''}
                    <td>\${Row.remark || '-'}</td>
                    <td>\${Row.protocol}</td>
                    <td class="domain-hosting-cell"><span class="hosting-badge \${hostingClass}">\${hosting}</span></td>
                    <td class="config-data-cell">\${Row.config_data.substring(0, 40)}...</td>
                    <td class="actions-cell">
                      \${isOverview ? 
                        \`<button class="nav-btn" onclick="loadUuid('\${Row.uuid}')">管理</button>\` : 
                        \`<button class="nav-btn" data-config="\${sc}" onclick="openEditModal(JSON.parse(this.dataset.config))">编辑</button>
                         <button class="nav-btn" style="background:#d44;color:#fff;border-color:#d44" onclick="delOne(\${Row.id})">删除</button>\`
                      }
                    </td>
                  </tr>
                \`;
              });
              h += '</tbody></table></div>'; 
              c.innerHTML = h;

              // Enable/disable buttons based on view mode and config existence
              document.getElementById('deleteAllBtn').disabled = isOverview; // Disable in overview
              document.querySelector('#addCard .nav-btn.primary').disabled = isOverview; // Disable in overview
            }
        }
      
        // Load stats
        await loadUuidStats();
      
      } catch(e) { 
        showToast('查询失败: ' + e.message,'error'); 
        document.getElementById('queryResultsContainer').innerHTML = '<p style="padding:20px;text-align:center;color:#89949B">加载配置失败，请检查网络或权限。</p>';
        document.getElementById('statsSummary').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">无法加载统计数据</div>';
        if (statsChart) { statsChart.destroy(); statsChart = null; }
        document.getElementById('recentLogs').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">无法加载访问记录</div>';
        document.getElementById('deleteAllBtn').disabled = true;
        document.querySelector('#addCard .nav-btn.primary').disabled = true;
      } finally { 
        setButtonLoading(b, false); 
      }
    }
  
    // 添加配置
    async function manageAddConfig(){
      const u = currentUuid; // Use currentUuid directly
      const d = document.getElementById('addConfigData').value.trim();
      const hosting = document.getElementById('domainHostingSelect').value;
    
      if (currentViewMode !== 'single' || !u || u === '_all_') {
          showToast('请选择或生成一个Config UUID后再添加配置', 'error');
          return;
      }
      if (!userToken) { showToast('请登录以添加配置', 'error'); return; }
      if(!d) { showToast('配置数据不能为空','error'); return; }
    
      const headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + userToken };
      const button = document.querySelector('#addCard .nav-btn.primary');
      setButtonLoading(button, true);
    
      try { 
          const response = await fetch('/manage/configs', {
            method: 'POST', 
            headers: headers,
            body: JSON.stringify({ uuid: u, config_data: d, domain_hosting: hosting })
          });
        
          const result = await response.json();
          if (response.status === 401) {
              showToast('会话已过期，请重新登录', 'error');
              clearUserLocalStorage(); updateUIForGuest(); return;
          } else if (result.success) {
              showToast('添加成功','success'); 
              document.getElementById('addConfigData').value = ''; 
              await manageQueryByUuid(); // Refresh config list for current UUID
              await loadUserUuids(); // Refresh user's overall Config UUID list
              if (userInfo && result.message) { 
                  const addedCountMatch = result.message.match(/(\\d+)/);
                  if (addedCountMatch) {
                      userInfo.stats.configs.total = (userInfo.stats.configs.total || 0) + parseInt(addedCountMatch[1]);
                      // Also update owned_uuids if this was a new UUID
                      const currentUuids = await getUserUuidsClient(); // Get current UUIDs from backend
                      if (!currentUuids.includes(u)) { // If this was the first config for this UUID, increment count
                         userInfo.stats.configs.uuids++;
                      }
                      await loadUserStats(); // Refresh user dashboard stats
                  }
              }
          } else {
              showToast(result.error || '添加失败','error');
          }
      } catch (error) { showToast('网络错误: ' + error.message, 'error'); } 
      finally { setButtonLoading(button, false); }
    }
  
    // 获取用户Config UUID列表 (客户端版本)
    async function getUserUuidsClient() {
        if (!userToken) return [];
        try {
            const response = await fetch('/api/user/uuids', {
                headers: { 'Authorization': 'Bearer ' + userToken }
            });
            const data = await response.json();
            return data.success ? data.uuids : [];
        } catch (e) {
            console.error("Error fetching user UUIDs client-side:", e);
            return [];
        }
    }

    // 删除单个配置
    async function delOne(id){ 
      if (!userToken) { showToast('请登录以删除配置', 'error'); return; }
      if (!currentUuid || currentUuid === '_all_') {
          showToast('无法在总览模式下删除，请选择单个Config UUID', 'error');
          return;
      }
      if(!confirm('确认删除此条配置?')) return;
    
      const headers = { 'Authorization': 'Bearer ' + userToken };
    
      try { 
          const response = await fetch(\`/manage/configs/id/\${id}\`, {
            method: 'DELETE',
            headers: headers
          }); 
          const result = await response.json();
          if (response.status === 401) {
              showToast('会话已过期，请重新登录', 'error');
              clearUserLocalStorage(); updateUIForGuest(); return;
          } else if (result.success) {
            showToast('删除成功', 'success');
            await manageQueryByUuid(); // Refresh config list
            await loadUserUuids(); // Refresh user's overall Config UUID list
            if (userInfo && userInfo.stats.configs.total > 0) { // Update user's total config count
                userInfo.stats.configs.total--;
                // Re-evaluate owned_uuids count after deletion, if this was the last config for a UUID
                const currentUuids = await getUserUuidsClient(); 
                userInfo.stats.configs.uuids = currentUuids.length;
                await loadUserStats(); // Refresh user dashboard stats
            }
          } else {
            showToast(result.error || result.message || '删除失败', 'error');
          }
      } catch (error) { showToast('删除失败: ' + error.message, 'error'); }
    }
  
    // 删除当前Config UUID下的所有配置 (unchanged logic, but depends on currentUuid)
    async function deleteAll(){ 
      const u = currentUuid; 
      if (!u || u === '_all_') {
          showToast('请选择一个Config UUID进行删除操作', 'error');
          return;
      }
      if(!confirm(\`确认清空当前Config UUID (\${u.substring(0,8)}...) 下的所有配置? 此操作不可逆！\`)) return;
      if (!userToken) { showToast('请登录以删除配置', 'error'); return; }
    
      const headers = { 'Authorization': 'Bearer ' + userToken };
    
      try { 
          const response = await fetch(\`/manage/configs/\${u}\`, {
            method: 'DELETE',
            headers: headers
          }); 
          const result = await response.json();
          if (response.status === 401) {
              showToast('会话已过期，请重新登录', 'error');
              clearUserLocalStorage(); updateUIForGuest(); return;
          } else if (result.success) {
            showToast(\`成功删除 \${result.message.match(/(\\d+)/)[1]} 条配置\`, 'success');
            await manageQueryByUuid(); // Refresh config list (which should now be empty)
            await loadUserUuids(); // Refresh user's overall Config UUID list
            if (userInfo && result.message) {
                const deletedCountMatch = result.message.match(/(\\d+)/);
                if (deletedCountMatch) {
                    userInfo.stats.configs.total = Math.max(0, userInfo.stats.configs.total - parseInt(deletedCountMatch[1]));
                    // This UUID group is likely empty now, so update owned_uuids client-side
                    const currentUuids = await getUserUuidsClient(); 
                    userInfo.stats.configs.uuids = currentUuids.length;
                    await loadUserStats(); // Refresh user dashboard stats
                }
            }
          } else {
            showToast(result.error || result.message || '删除失败', 'error');
          }
      } catch (error) { showToast('删除失败: ' + error.message, 'error'); }
    }
    
    // 加载UUID统计 (now uses currentUuid, which could be _all_)
    async function loadUuidStats() {
      const uuidToQuery = currentUuid;
      if (!uuidToQuery) return; // Wait until a UUID (or _all_) is set
      if (!userToken) { showToast('请登录以查看统计', 'error'); return; }
    
      const days = document.getElementById('statsDays').value;
      const headers = { 'Authorization': 'Bearer ' + userToken };
    
      try {
        const response = await fetch(\`/manage/stats/\${uuidToQuery}?days=\${days}\`, { headers });
        const data = await response.json();
        
        if (response.status === 401) {
            showToast('会话已过期，请重新登录', 'error');
            clearUserLocalStorage(); updateUIForGuest(); return;
        } else if (data.success) {
          displayStatsSummary(data);
          renderStatsChart(data.daily_stats);
          displayRecentLogs(data.recent_logs);
          updateChartButtons(); // Ensure chart buttons reflect current state
        } else { 
          document.getElementById('statsSummary').innerHTML = \`
            <div style="text-align: center; padding: 20px; color: #6b7280;">
              <p>\${data.error || '无统计信息'}</p>
            </div>
          \`;
          if (statsChart) { statsChart.destroy(); statsChart = null; }
          document.getElementById('recentLogs').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无访问记录</div>';
        }
      } catch (error) { 
        document.getElementById('statsSummary').innerHTML = \`
          <div style="text-align: center; padding: 20px; color: #6b7280;">
            <p>获取统计失败: \${error.message}</p>
          </div>
        \`;
        if (statsChart) { statsChart.destroy(); statsChart = null; }
        document.getElementById('recentLogs').innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无访问记录</div>';
      }
    }
  
    function displayStatsSummary(stats) {
      const container = document.getElementById('statsSummary');
    
      const subscriptionTotal = stats.subscription_count || 0;
      const apigenTotal = stats.apigen_count || 0;
      const totalAccess = stats.total_access || 0;
    
      const subscriptionPercent = totalAccess > 0 ? 
        Math.round(subscriptionTotal / totalAccess * 100) : 0;
      const apigenPercent = totalAccess > 0 ? 
        Math.round(apigenTotal / totalAccess * 100) : 0;
    
      container.innerHTML = \`
        <div class="stat-box">
          <span class="stat-num">\${totalAccess}</span>
          <span class="stat-label">总访问次数</span>
          <span class="stat-sub">首次: \${stats.first_access ? formatDateTime(stats.first_access) : '从未'}</span>
        </div>
        <div class="stat-box">
          <span class="stat-num">\${stats.today_total || 0}</span>
          <span class="stat-label">今日访问</span>
          <span class="stat-sub">订阅:\${stats.today_subscription || 0} | 网页:\${stats.today_apigen || 0}</span>
        </div>
        <div class="stat-box">
          <span class="stat-num">\${subscriptionTotal}</span>
          <span class="stat-label">订阅访问</span>
          <span class="stat-sub">占比 \${subscriptionPercent}%</span>
        </div>
        <div class="stat-box">
          <span class="stat-num">\${apigenTotal}</span>
          <span class="stat-label">网页生成</span>
          <span class="stat-sub">占比 \${apigenPercent}%</span>
        </div>
      \`;
    }
  
    function renderStatsChart(dailyStats) {
      const ctx = document.getElementById('statsChart').getContext('2d');
      if (statsChart) { statsChart.destroy(); }
      if (!dailyStats || dailyStats.length === 0) { 
        ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
        ctx.font = '14px Arial';
        ctx.fillStyle = '#6b7280';
        ctx.textAlign = 'center';
        ctx.fillText('暂无统计数据', ctx.canvas.width / 2, ctx.canvas.height / 2);
        return; 
      }
      const dates = dailyStats.map(item => formatDate(item.date));
      const totals = dailyStats.map(item => item.total);
      const subscriptions = dailyStats.map(item => item.subscription);
      const apigens = dailyStats.map(item => item.api_generation);
      let datasets = [];
      if (currentChartType === 'total') {
        datasets = [{
          label: '总访问量',
          data: totals,
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        }];
      } else {
        datasets = [
          {
            label: '订阅访问',
            data: subscriptions,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          },
          {
            label: '网页生成',
            data: apigens,
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          }
        ];
      }
      statsChart = new Chart(ctx, {
        type: 'line',
        data: { labels: dates, datasets: datasets },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'top' },
            title: {
              display: true,
              text: currentViewMode === 'overview' ? '所有Config UUID 访问趋势' : \`Config UUID: \${currentUuid.substring(0, 8)}... 访问趋势\`
            }
          },
          scales: {
            x: {
              grid: { display: false },
              title: { display: true, text: '日期' }
            },
            y: {
              beginAtZero: true,
              ticks: { precision: 0 },
              title: { display: true, text: '访问次数' }
            }
          }
        }
      });
    }

    function displayRecentLogs(logs) {
      const container = document.getElementById('recentLogs');
    
      if (!logs || logs.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 20px; color: #6b7280;">暂无访问记录</div>';
        return;
      }
    
      let html = '';
      logs.forEach(log => {
        const typeClass = log.query_type === 'subscription' ? 'type-subscription' : 'type-apigen';
        const typeText = log.query_type === 'subscription' ? '订阅请求' : '网页生成';
        const userAgentShort = log.user_agent ? 
          (log.user_agent.length > 50 ? log.user_agent.substring(0, 50) + '...' : log.user_agent) : 
          '未知';
      
        html += \`
          <div class="access-log-item">
            <div>
              <span class="timestamp">\${formatDateTime(log.created_at)}</span>
              <span class="log-type \${typeClass}">\${typeText}</span>
              \${currentViewMode === 'overview' ? \`<span style="margin-left:8px; color:#89949B; font-size:0.8em; font-weight:normal;">(UUID: \${log.uuid.substring(0,8)}...)</span>\` : ''}
            </div>
            <div style="color: #6b7280; font-size: 0.8rem;" title="\${log.user_agent || '未知'}">
              IP: \${log.client_ip || '未知'} | UA: \${userAgentShort}
            </div>
          </div>
        \`;
      });
    
      container.innerHTML = html;
    }
  
    function switchChartType(type) {
      currentChartType = type;
      updateChartButtons();
      if (currentUuid) {
        loadUuidStats();
      }
    }
  
    function updateChartButtons() {
      const totalBtn = document.getElementById('chartTotalBtn');
      const splitBtn = document.getElementById('chartSplitBtn');
    
      totalBtn.classList.toggle('active', currentChartType === 'total');
      splitBtn.classList.toggle('active', currentChartType === 'split');
    }
  
    // --- User Dashboard Functions ---

    function loadUserStats() {
      if (!userInfo) {
          document.getElementById('userConfigCount').textContent = 'N/A';
          document.getElementById('userUuidCount').textContent = 'N/A';
          document.getElementById('userAccessCount').textContent = 'N/A';
          document.getElementById('userProtocols').textContent = 'N/A';
          return;
      }
    
      document.getElementById('userConfigCount').textContent = userInfo.stats.configs.total || 0;
      document.getElementById('userUuidCount').textContent = userInfo.stats.configs.uuids || 0;
      document.getElementById('userAccessCount').textContent = userInfo.stats.access.total || 0;
      document.getElementById('userProtocols').textContent = userInfo.stats.configs.protocols?.length || 0;
    }
  
    function showUserDashboard() {
      if (!userToken) { showToast('请登录以访问用户仪表板', 'error'); return; }

      document.getElementById('userDashboard').classList.remove('hidden');
      // Hide other management cards
      document.getElementById('resultCard').classList.add('hidden');
      document.getElementById('statsCard').classList.add('hidden');
      document.getElementById('addCard').classList.add('hidden');
      // Ensure latest stats and UUIDs are loaded for the dashboard
      loadUserStats();
      loadUserUuids(); 
    }
  
    function hideUserDashboard() {
      document.getElementById('userDashboard').classList.add('hidden');
      // Show management cards IF a UUID is currently being managed
      if (currentUuid) { 
        document.getElementById('resultCard').classList.remove('hidden');
        document.getElementById('statsCard').classList.remove('hidden');
        document.getElementById('addCard').classList.remove('hidden');
      }
    }

    // --- Edit Modal Functions ---
    function openEditModal(config) {
      if (currentViewMode !== 'single') {
          showToast('无法在总览模式下编辑，请选择单个Config UUID', 'error');
          return;
      }
      if (!userToken) { showToast('请登录以编辑配置', 'error'); return; }

      const modal = document.getElementById('editModalOverlay');
      document.getElementById('edit-id').value = config.id;
    
      let p = 'unknown'; 
      const l = config.config_data;
      if(l.startsWith('vmess://')) p='vmess'; 
      else if(l.startsWith('vless://')) p='vless'; 
      else if(l.startsWith('trojan://')) p='trojan';
      else if(l.startsWith('hysteria2://')) p='hysteria2';
      else if(l.startsWith('tuic://')) p='tuic';
      else if(l.startsWith('anytls://')) p='anytls';
      else if(l.startsWith('socks5://')) p='socks5';
      else if(l.startsWith('any-reality://')) p='any-reality';
      else if(l.startsWith('ss://')) p='ss';
    
      document.getElementById('edit-protocol').value = p;
      ['ps','add','port','id-uuid','net','type','host','path','tls','sni'].forEach(
        k => document.getElementById('edit-'+k).value = ''
      );
    
      const hostingSelect = document.getElementById('edit-domain-hosting');
      hostingSelect.value = config.domain_hosting || 'Cloudflare';
    
      try {
        if (p === 'vmess') {
          const c = JSON.parse(b64DecodeUnicode(l.substring(8)));
          document.getElementById('edit-ps').value = c.ps || ''; 
          document.getElementById('edit-add').value = c.add || ''; 
          document.getElementById('edit-port').value = c.port || ''; 
          document.getElementById('edit-id-uuid').value = c.id || ''; 
          document.getElementById('edit-net').value = c.net || 'tcp'; 
          document.getElementById('edit-type').value = c.type === "none" ? "" : c.type || ''; 
          document.getElementById('edit-host').value = c.host || ''; 
          document.getElementById('edit-path').value = c.path || ''; 
          document.getElementById('edit-tls').value = c.tls || ''; 
          document.getElementById('edit-sni').value = c.sni || '';
        } else {
          const u = new URL(l);
          document.getElementById('edit-ps').value = u.hash ? decodeURIComponent(u.hash.substring(1)) : ''; 
          document.getElementById('edit-add').value = u.hostname; 
          document.getElementById('edit-port').value = u.port || ''; 
          document.getElementById('edit-id-uuid').value = u.username; 
          document.getElementById('edit-net').value = u.searchParams.get('type') || (u.protocol.slice(0, -1) === 'vless' ? 'ws' : u.protocol.slice(0,-1)) || 'tcp'; // Default vless to ws
          document.getElementById('edit-type').value = u.searchParams.get('headerType') || ''; 
          document.getElementById('edit-host').value = u.searchParams.get('host') || ''; 
          document.getElementById('edit-path').value = u.searchParams.get('serviceName') || u.searchParams.get('path') || ''; 
          document.getElementById('edit-tls').value = u.searchParams.get('security') === 'tls' ? 'tls' : ''; 
          document.getElementById('edit-sni').value = u.searchParams.get('sni') || '';
        }
      } catch(e) { 
        showToast('配置解析失败，请检查格式: ' + e.message, 'error'); 
        return; 
      }
    
      modal.classList.add('open');
    }
  
    function closeEditModal() { 
      document.getElementById('editModalOverlay').classList.remove('open'); 
    }
  
    async function saveEditedConfig() {
      const id = document.getElementById('edit-id').value;
      const proto = document.getElementById('edit-protocol').value;
      const ps = document.getElementById('edit-ps').value.trim();
      const add = document.getElementById('edit-add').value.trim();
      const port = document.getElementById('edit-port').value.trim();
      const uuid = document.getElementById('edit-id-uuid').value.trim();
      const net = document.getElementById('edit-net').value.trim();
      const type = document.getElementById('edit-type').value.trim();
      const host = document.getElementById('edit-host').value.trim();
      const path = document.getElementById('edit-path').value.trim();
      const tls = document.getElementById('edit-tls').value; // 'tls' or ''
      const sni = document.getElementById('edit-sni').value.trim();
      const domainHosting = document.getElementById('edit-domain-hosting').value;
    
      if (!userToken) { showToast('请登录以保存配置', 'error'); return; }
      if (!add || !port || !uuid) { showToast('地址、端口和UUID/密码不能为空', 'error'); return; }

      let nL = '';
      try {
        if (proto === 'vmess') {
          nL = 'vmess://' + b64EncodeUnicode(JSON.stringify({
            v: "2", ps, add, port: parseInt(port), id: uuid, aid: "0", scy: "auto",
            net, type:(type === "" ? "none" : type), host, path, tls, sni
          }));
        } else {
          const urlBase = \`\${proto}://\${uuid}@\${add}:\${port}\`;
          const u = new URL(urlBase);
        
          if (net && net !== 'tcp' && proto !== 'trojan') { 
              u.searchParams.set('type', net);
          } else {
              u.searchParams.delete('type');
          }
          if (type) u.searchParams.set('headerType', type); else u.searchParams.delete('headerType');
          
          if (tls === 'tls') {
              u.searchParams.set('security', 'tls');
              if (sni) u.searchParams.set('sni', sni); else u.searchParams.delete('sni');
          } else {
              u.searchParams.delete('security');
              u.searchParams.delete('sni');
          }
          
          if (host) u.searchParams.set('host', host); else u.searchParams.delete('host');
          
          if (path) {
              if (net === 'grpc' || proto === 'grpc') u.searchParams.set('serviceName', path);
              else u.searchParams.set('path', path);
          } else {
              u.searchParams.delete('path');
              u.searchParams.delete('serviceName');
          }

          if (ps) u.hash = encodeURIComponent(ps);
          else u.hash = ''; 

          nL = u.toString();
        }
      } catch (e) {
        showToast('生成配置链接失败，请检查输入: ' + e.message, 'error');
        return;
      }
    
      const b = document.querySelector('#editModalOverlay .nav-btn.primary');
      setButtonLoading(b, true);
    
      const headers = { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + userToken
      };
    
      try {
        const r = await fetch('/manage/configs', {
          method: 'PUT',
          headers: headers,
          body: JSON.stringify({
            id, 
            config_data: nL,
            domain_hosting: domainHosting
          })
        });
      
        const result = await r.json();
        if (r.status === 401) {
            showToast('会话已过期，请重新登录', 'error');
            clearUserLocalStorage(); updateUIForGuest(); return;
        } else if (result.success) {
          showToast('保存成功', 'success');
          closeEditModal();
          await manageQueryByUuid(); // Refresh current display
        } else {
          showToast(result.error || '保存失败', 'error');
        }
      } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
      } finally {
        setButtonLoading(b, false);
      }
    }
  </script>
</body>
</html>
`;
