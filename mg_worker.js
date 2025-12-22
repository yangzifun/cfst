/* =================================================================
 * Cloudflare Worker: YZFN Configuration Management (Enhanced)
 * ================================================================= */

// =================================================================
//  1. 后端工具与安全 (Hash, JWT, Response)
// =================================================================

async function hashPassword(password) {
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signJwt(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

async function verifyJwt(token, secret) {
    try {
        const [h, p, s] = token.split('.');
        if (!h || !p || !s) return false;
        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const signature = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        const valid = await crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(`${h}.${p}`));
        if (!valid) return false;
        const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp < Date.now()) return false;
        return payload;
    } catch (e) { return false; }
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

// =================================================================
//  2. IP 获取逻辑
// =================================================================

async function fetchIpsFromHostMonit() {
    try {
        const res = await fetch('https://api.hostmonit.com/get_optimization_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: "iDetkOys" })
        });
        if (!res.ok) return [];
        const data = await res.json();
        return (data.code === 200 && Array.isArray(data.info)) ? data.info.map(i => ({
            ip: i.ip.includes(':') ? `[${i.ip}]` : i.ip,
            ip_type: i.ip.includes(':') ? 'v6' : 'v4',
            carrier: i.line
        })) : [];
    } catch (e) { console.error("HostMonit Err", e); return []; }
}

async function fetchIpsFromVps789() {
    try {
        const res = await fetch('https://vps789.com/openApi/cfIpApi', { headers: { 'User-Agent': 'CF-Worker/4.0' } });
        if (!res.ok) return [];
        const data = await res.json();
        const ips = [];
        if (data.code === 0 && data.data) {
            for (const k in data.data) {
                const arr = data.data[k];
                if (Array.isArray(arr)) {
                    let c = ['CT', 'CU', 'CM'].includes(k) ? k : 'ALL';
                    arr.forEach(i => ips.push({
                        ip: i.ip.includes(':') ? `[${i.ip}]` : i.ip,
                        ip_type: i.ip.includes(':') ? 'v6' : 'v4',
                        carrier: c
                    }));
                }
            }
        }
        return ips;
    } catch (e) { console.error("Vps789 Err", e); return []; }
}

async function runIpUpdateTask(env, sources = null) {
    console.log(`[${new Date().toISOString()}] 开始IP更新任务...`);
    
    // 如果未指定sources，则从数据库读取配置
    if (sources === null) {
        try {
            const settingsRes = await env.DB.prepare(
                'SELECT source, enabled FROM auto_update_settings WHERE source IN (?, ?)'
            ).bind('hostmonit', 'vps789').all();
            
            if (settingsRes && settingsRes.results) {
                sources = {};
                settingsRes.results.forEach(setting => {
                    sources[setting.source] = setting.enabled === 1;
                });
                console.log(`从数据库读取配置: hostmonit=${sources.hostmonit}, vps789=${sources.vps789}`);
            } else {
                sources = { hostmonit: true, vps789: true };
            }
        } catch (e) {
            console.error("读取自动更新配置失败:", e);
            sources = { hostmonit: true, vps789: true };
        }
    }

    const tasks = [];
    if (sources.hostmonit !== false) tasks.push(fetchIpsFromHostMonit());
    if (sources.vps789 !== false) tasks.push(fetchIpsFromVps789());

    // 检查是否有启用的任务
    if (tasks.length === 0) {
        console.log("没有启用的API源，跳过更新");
        return { success: false, message: "没有启用的API源，更新已跳过" };
    }

    const results = await Promise.allSettled(tasks);
    console.log(`API调用结果: ${results.filter(r => r.status === 'fulfilled').length}成功, ${results.filter(r => r.status === 'rejected').length}失败`);
    
    const allIps = results
        .filter(r => r.status === 'fulfilled')
        .map(r => r.value)
        .flat();

    const uniqueMap = new Map();
    allIps.forEach(i => { if (i.ip) uniqueMap.set(i.ip, i); });
    const uniqueIps = Array.from(uniqueMap.values());

    if (uniqueIps.length === 0) {
        const error = "未能获取到任何有效IP，请检查API源是否可用";
        console.error(error);
        return { success: false, message: error, count: 0 };
    }

    try {
        // 检查是否开启自动更新
        const globalSetting = await env.DB.prepare(
            'SELECT enabled FROM auto_update_settings WHERE source = ?'
        ).bind('global_enabled').first();
        
        if (globalSetting && globalSetting.enabled === 0) {
            console.log("自动更新已关闭，跳过数据库更新");
            return { 
                success: true, 
                count: uniqueIps.length, 
                message: `获取到 ${uniqueIps.length} 个IP，但自动更新已关闭，未保存到数据库`,
                data: uniqueIps.slice(0, 10) // 返回前10个示例
            };
        }

        // 清理旧数据并插入新数据
        await env.DB.prepare('DELETE FROM cfips').run();
        
        const stmts = uniqueIps.map(i =>
            env.DB.prepare('INSERT INTO cfips (ip, ip_type, carrier, created_at) VALUES (?, ?, ?, ?)')
                .bind(i.ip, i.ip_type, i.carrier, Date.now())
        );
        
        const BATCH_SIZE = 50;
        for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
            const batch = stmts.slice(i, i + BATCH_SIZE);
            console.log(`插入批次 ${Math.floor(i/BATCH_SIZE) + 1}/${Math.ceil(stmts.length/BATCH_SIZE)}: ${batch.length}条记录`);
            await env.DB.batch(batch);
        }
        
        // 更新最后执行时间
        await env.DB.prepare(
            'INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)'
        ).bind('last_executed', 1, Date.now()).run();
        
        console.log(`[${new Date().toISOString()}] IP更新完成: ${uniqueIps.length}条记录`);
        return { 
            success: true, 
            count: uniqueIps.length, 
            message: `成功更新 ${uniqueIps.length} 个 IP`,
            timestamp: Date.now()
        };
        
    } catch (e) {
        console.error("数据库更新失败:", e);
        return { success: false, message: "数据库错误: " + e.message };
    }
}

// =================================================================
//  3. API 路由处理 (增加自动更新设置相关API)
// =================================================================

async function handleApi(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // Login & Auth
    if (path === '/api/login' && method === 'POST') {
        const { username, password } = await req.json();
        const user = await env.DB.prepare('SELECT * FROM admin_users WHERE username = ?').bind(username).first();
        if (!user || (await hashPassword(password)) !== user.password_hash) return jsonResponse({ error: '用户名或密码错误' }, 401);
        const token = await signJwt({ sub: user.username, exp: Date.now() + 86400000 }, env.JWT_SECRET || 'secret');
        return jsonResponse({ token });
    }

    const authHeader = req.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return jsonResponse({ error: '未授权' }, 401);
    const payload = await verifyJwt(authHeader.split(' ')[1], env.JWT_SECRET || 'secret');
    if (!payload) return jsonResponse({ error: 'Token 无效或过期' }, 401);
    const currentUser = payload.sub;

    if (path === '/api/change-password' && method === 'POST') {
        const { oldPassword, newPassword } = await req.json();
        const user = await env.DB.prepare('SELECT * FROM admin_users WHERE username = ?').bind(currentUser).first();
        if ((await hashPassword(oldPassword)) !== user.password_hash) return jsonResponse({ error: '旧密码错误' }, 403);
        await env.DB.prepare('UPDATE admin_users SET password_hash = ? WHERE username = ?').bind(await hashPassword(newPassword), currentUser).run();
        return jsonResponse({ success: true });
    }

    if (path === '/api/stats') {
        const d = await env.DB.prepare('SELECT COUNT(*) as c FROM cf_domains').first('c');
        const i = await env.DB.prepare('SELECT COUNT(*) as c FROM cfips').first('c');
        const u = await env.DB.prepare('SELECT COUNT(DISTINCT uuid) as c FROM configs').first('c');
        const enabled = await env.DB.prepare('SELECT enabled FROM auto_update_settings WHERE source = ?').bind('global_enabled').first('enabled');
        const lastExec = await env.DB.prepare('SELECT updated_at FROM auto_update_settings WHERE source = ?').bind('last_executed').first('updated_at');
        return jsonResponse({ 
            domains: d, 
            ips: i, 
            uuids: u,
            autoUpdate: enabled || 0,
            lastExecuted: lastExec || 0
        });
    }

    // --- Auto Update Settings API ---
    if (path === '/api/settings/auto-update' && method === 'GET') {
        const settings = await env.DB.prepare(
            'SELECT source, enabled, updated_at FROM auto_update_settings WHERE source IN (?, ?, ?)'
        ).bind('global_enabled', 'hostmonit', 'vps789').all();
        
        const result = { global_enabled: 0, hostmonit: 1, vps789: 1 };
        if (settings && settings.results) {
            settings.results.forEach(setting => {
                result[setting.source] = setting.enabled;
            });
        }
        return jsonResponse(result);
    }

    if (path === '/api/settings/auto-update' && method === 'POST') {
        const { global_enabled, hostmonit, vps789 } = await req.json();
        
        const stmts = [
            env.DB.prepare('INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)')
                .bind('global_enabled', global_enabled ? 1 : 0, Date.now()),
            env.DB.prepare('INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)')
                .bind('hostmonit', hostmonit ? 1 : 0, Date.now()),
            env.DB.prepare('INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)')
                .bind('vps789', vps789 ? 1 : 0, Date.now())
        ];
        
        await env.DB.batch(stmts);
        return jsonResponse({ success: true });
    }

    // --- Domains API ---
    if (path === '/api/domains') {
        if (method === 'GET') {
            const page = parseInt(url.searchParams.get('page')) || 1;
            const size = parseInt(url.searchParams.get('size')) || 10;
            const sortField = url.searchParams.get('sort') || 'id';
            const sortOrder = (url.searchParams.get('order') || 'desc').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
            const allowedSorts = ['id', 'domain', 'remark', 'created_at'];
            const actualSort = allowedSorts.includes(sortField) ? sortField : 'id';
            const offset = (page - 1) * size;

            const total = await env.DB.prepare('SELECT COUNT(*) as c FROM cf_domains').first('c');
            const query = `SELECT * FROM cf_domains ORDER BY ${actualSort} ${sortOrder} LIMIT ? OFFSET ?`;
            const { results } = await env.DB.prepare(query).bind(size, offset).all();

            return jsonResponse({ total, data: results, page, size });
        }
        if (method === 'POST') {
            const { domain, remark } = await req.json();
            if(!domain) return jsonResponse({error:'Missing domain'}, 400);
            await env.DB.prepare('INSERT INTO cf_domains (domain, remark, created_at) VALUES (?, ?, ?)').bind(domain, remark || '', Date.now()).run();
            return jsonResponse({ success: true });
        }
        if (method === 'PUT') {
            const { id, domain, remark } = await req.json();
            if(!id || !domain) return jsonResponse({error:'Missing id or domain'}, 400);
            await env.DB.prepare('UPDATE cf_domains SET domain = ?, remark = ? WHERE id = ?').bind(domain, remark || '', id).run();
            return jsonResponse({ success: true });
        }
        if (method === 'DELETE') {
            await env.DB.prepare('DELETE FROM cf_domains WHERE id = ?').bind((await req.json()).id).run();
            return jsonResponse({ success: true });
        }
    }

    // --- IPs API ---
    if (path === '/api/ips') {
        if (method === 'GET') {
            const page = parseInt(url.searchParams.get('page')) || 1;
            const size = parseInt(url.searchParams.get('size')) || 20;
            const sortField = url.searchParams.get('sort') || 'created_at';
            const sortOrder = (url.searchParams.get('order') || 'desc').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
            
            const allowedSorts = ['ip', 'ip_type', 'carrier', 'created_at'];
            const actualSort = allowedSorts.includes(sortField) ? sortField : 'created_at';
            const offset = (page - 1) * size;

            const total = await env.DB.prepare('SELECT COUNT(*) as c FROM cfips').first('c');
            const query = `SELECT * FROM cfips ORDER BY ${actualSort} ${sortOrder} LIMIT ? OFFSET ?`;
            const { results } = await env.DB.prepare(query).bind(size, offset).all();

            return jsonResponse({ total, data: results, page, size });
        }
        if (method === 'DELETE') {
            await env.DB.prepare('DELETE FROM cfips WHERE ip = ?').bind((await req.json()).ip).run();
            return jsonResponse({ success: true });
        }
    }
    if (path === '/api/ips/refresh' && method === 'POST') {
        const body = await req.json().catch(() => ({}));
        const res = await runIpUpdateTask(env, body);
        return jsonResponse(res);
    }
    
    // --- UUIDs API ---
    if (path === '/api/uuids') {
        if (method === 'GET') {
            const page = parseInt(url.searchParams.get('page')) || 1;
            const size = parseInt(url.searchParams.get('size')) || 10;
            const sortField = url.searchParams.get('sort') || 'updated_at';
            const sortOrder = (url.searchParams.get('order') || 'desc').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
            
            const allowedSorts = ['uuid', 'count', 'updated_at'];
            const actualSort = allowedSorts.includes(sortField) ? sortField : 'updated_at';
            const offset = (page - 1) * size;

            const total = await env.DB.prepare('SELECT COUNT(DISTINCT uuid) as c FROM configs').first('c');
            const query = `SELECT uuid, COUNT(*) as count, MAX(created_at) as updated_at FROM configs GROUP BY uuid ORDER BY ${actualSort} ${sortOrder} LIMIT ? OFFSET ?`;
            const { results } = await env.DB.prepare(query).bind(size, offset).all();

            return jsonResponse({ total, data: results, page, size });
        }
        if (method === 'DELETE') {
            await env.DB.prepare('DELETE FROM configs WHERE uuid = ?').bind((await req.json()).uuid).run();
            return jsonResponse({ success: true });
        }
    }

    return new Response('Not Found', { status: 404 });
}

// =================================================================
//  4. 主入口 & HTML 模板
// =================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        if (url.pathname.startsWith('/api')) return await handleApi(request, env);
        if (url.pathname === '/login') return new Response(loginHtml, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        return new Response(adminHtml, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    },
    
    // 定时任务处理器 - 由Cloudflare Cron Triggers触发
    async scheduled(event, env, ctx) {
        ctx.waitUntil((async () => {
            console.log(`[${new Date().toISOString()}] 定时IP更新任务开始执行`);
            try {
                await runIpUpdateTask(env);
                console.log(`[${new Date().toISOString()}] 定时IP更新任务完成`);
            } catch (error) {
                console.error(`[${new Date().toISOString()}] 定时IP更新任务失败:`, error);
            }
        })());
    }
};

// =================================================================
//  5. 前端HTML模板
// =================================================================

const globalCss = `
html { font-size: 87.5%; } body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { width: 100%; min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 20px 20px 40px; box-sizing: border-box; }
.content-group { width: 100%; max-width: 900px; text-align: center; margin-top: 20px; }
.profile-name { font-size: 2rem; color: #3d474d; margin-bottom: 5px; font-weight: bold;}
.profile-quote { color: #89949B; margin-bottom: 10px; min-height: 1em; }
.top-bar { width: 100%; max-width: 900px; display: flex; justify-content: space-between; margin-bottom: 20px; align-items: center; padding: 0 5px; box-sizing: border-box; }
.action-link { font-size: 0.9rem; color: #89949B; cursor: pointer; text-decoration: none; margin-right: 15px; transition: color 0.2s; }
.action-link:hover { color: #5a666d; text-decoration: underline; }
.action-link.logout { color: #e16d6d; }
.action-link.logout:hover { color: #d32f2f; }
.nav-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-bottom: 25px; border-bottom: 1px solid #E8EBED; padding-bottom: 20px; }
.nav-btn { display: inline-flex; align-items: center; justify-content: center; padding: 8px 16px; background: #E8EBED; border: 2px solid #89949B; border-radius: 4px; color: #5a666d; font-weight: 500; font-size: 0.95rem; cursor: pointer; transition: all 0.2s; white-space: nowrap; text-decoration: none; }
.nav-btn:hover { background: #89949B; color: white; }
.nav-btn.active { background-color: #5a666d; color: white; border-color: #5a666d; }
.nav-btn.danger { border-color: #ef4444; color: #ef4444; background: #fee2e2; }
.nav-btn.danger:hover { background: #ef4444; color: white; }
.nav-btn.small { padding: 4px 10px; font-size: 0.85rem; }
.card { background: #f8f9fa; border: 1px solid #E8EBED; border-radius: 8px; padding: 24px; margin-bottom: 24px; text-align: left; display: none; animation: fadeIn 0.3s ease; }
.card.active { display: block; }
.card h2 { font-size: 1.4rem; color: #3d474d; margin-top: 0; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #E8EBED; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px; background: #fff; font-size: 0.9rem; box-sizing: border-box; margin-bottom: 10px; }
input:focus { outline: none; border-color: #3d474d; }
.table-container { overflow-x: auto; border: 2px solid #89949B; border-radius: 4px; background: #fff; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #E8EBED; white-space: nowrap; }
th { font-weight: bold; color: #3d474d; background-color: #f0f2f5; cursor: pointer; user-select: none; }
th:hover { background-color: #e2e6ea; }
.pagination-bar { display: flex; justify-content: space-between; align-items: center; padding-top: 15px; font-size: 0.9rem; color: #5a666d; }
.page-ctrl { display: flex; gap: 5px; align-items: center; }
.page-info { margin: 0 10px; }
select.page-size { padding: 4px; border: 1px solid #89949B; border-radius: 4px; background: #fff; }
.footer { margin-top: auto; padding-top: 40px; color: #89949B; font-size: 0.8rem; text-align: center; width: 100%; border-top: 1px solid #f0f0f0; }
.footer a { color: #5a666d; text-decoration: none; }
.footer a:hover { text-decoration: underline; }
.switch-group { display: flex; gap: 20px; align-items: center; margin-bottom: 15px; background: #e8ebed; padding: 10px 15px; border-radius: 4px; }
.switch-label { font-weight: 500; color: #5a666d; display: flex; align-items: center; gap: 8px;}
.switch { position: relative; display: inline-block; width: 40px; height: 22px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
.slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
input:checked + .slider { background-color: #5a666d; }
input:checked + .slider:before { transform: translateX(18px); }
.auto-update-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
.auto-update-status { font-size: 0.9rem; color: #3d474d; padding: 5px 10px; background: #e8ebed; border-radius: 4px; display: inline-flex; align-items: center; gap: 8px; }
.status-indicator { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.status-on { background-color: #10b981; }
.status-off { background-color: #ef4444; }
#toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast { padding: 12px 18px; border-radius: 4px; border: 2px solid #89949B; background: #fff; color: #3d474d; font-weight: 500; font-size: 0.9rem; box-shadow: 0 4px 12px rgba(0,0,0,0.1); animation: slideIn 0.3s forwards, fadeOut 0.5s 3.5s forwards; }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
@keyframes fadeOut { to { opacity: 0; transform: translateX(100%); } }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100; display: none; align-items: center; justify-content: center; }
.modal { background: #fff; width: 90%; max-width: 380px; padding: 25px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
`;

const loginHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico">
    <title>优选配置管理后台 - 登录</title>
    <style>
        ${globalCss}
        body { display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; min-height: 500px; background: #f9fafb; }
        .login-box { width: 100%; max-width: 360px; padding: 40px 30px; border: 2px solid #89949B; border-radius: 8px; background: #fff; text-align: center; margin: auto; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); }
    </style>
</head>
<body>
    <div class="login-box">
        <h2 class="profile-name">优选配置管理后台</h2>
        <p class="profile-quote">请先验证身份</p>
        <div id="msg" style="color:#ef4444; font-size:0.9rem; margin-bottom:10px; display:none;"></div>
        <form onsubmit="doLogin(event)">
            <input type="text" id="user" placeholder="管理员账号" required>
            <input type="password" id="pass" placeholder="访问密码" required>
            <button type="submit" id="btn" class="nav-btn active" style="width:100%; margin-top:15px;">身份验证</button>
        </form>
    </div>
    <footer class="footer" style="border:none; width:auto; margin-top: 30px;">
        <p>Powered by <a href="https://www.yangzihome.space" target="_blank">YZFN</a> | <a href="https://www.yangzihome.space/security.html" target="_blank">安全声明</a></p>
    </footer>
    <script>
        if(localStorage.getItem('token')) window.location.href='/';
        async function doLogin(e) {
            e.preventDefault();
            const btn = document.getElementById('btn'), msg = document.getElementById('msg');
            btn.disabled = true; btn.innerText = '验证中...'; msg.style.display = 'none';
            try {
                const r = await fetch('/api/login', { method:'POST', body:JSON.stringify({ username: document.getElementById('user').value, password: document.getElementById('pass').value }) });
                const d = await r.json();
                if(d.token) { localStorage.setItem('token', d.token); window.location.href='/'; }
                else { msg.innerText = d.error || '验证失败'; msg.style.display = 'block'; }
            } catch(err) { msg.innerText = '连接服务器失败'; msg.style.display = 'block'; }
            btn.disabled = false; btn.innerText = '身份验证';
        }
    </script>
</body>
</html>
`;

const adminHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico">
    <title>优选配置管理后台</title>
    <style>${globalCss}
        .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-box { background: #e8ebed; padding: 20px; border-radius: 4px; text-align: center; }
        .stat-num { font-size: 2rem; color: #5a666d; font-weight: bold; display: block; }
        .stat-label { font-size: 0.85rem; color: #89949B; }
        .last-update-info { margin-top: 10px; font-size: 0.85rem; color: #3d474d; }
    </style>
</head>
<body>
    <div id="toast-container"></div>
    <div id="loader" style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);color:#89949B">System Loading...</div>

    <div class="container" id="app" style="display:none">
        <div class="top-bar">
            <div><span style="font-weight:bold; color:#5a666d;">CF 优选配置管理</span> <span style="color:#89949B; font-size:0.9rem;">| Admin</span></div>
            <div>
                <a class="action-link" onclick="openPwdModal()">修改密码</a>
                <a class="action-link logout" onclick="logout()">安全退出</a>
            </div>
        </div>

        <div class="content-group">
            <h1 class="profile-name">管理后台</h1>
            <div class="nav-grid">
                <button class="nav-btn active" onclick="switchTab('dash', this)">系统概览</button>
                <button class="nav-btn" onclick="switchTab('dom', this)">优选域名</button>
                <button class="nav-btn" onclick="switchTab('ips', this)">IP 资源池</button>
                <button class="nav-btn" onclick="switchTab('uuids', this)">配置分组</button>
            </div>

            <div id="dash" class="card active">
                <h2>系统状态</h2>
                <div class="stat-grid">
                    <div class="stat-box"><span class="stat-num" id="s-dom">-</span><span class="stat-label">优选域名</span></div>
                    <div class="stat-box"><span class="stat-num" id="s-ip">-</span><span class="stat-label">活跃 IP</span></div>
                    <div class="stat-box"><span class="stat-num" id="s-uuid">-</span><span class="stat-label">配置分组</span></div>
                </div>
                <div class="last-update-info">
                    自动更新状态: <span id="autoUpdateStatus">加载中...</span>
                    <br>最后执行时间: <span id="lastExecuted">未知</span>
                </div>
            </div>

            <div id="dom" class="card">
                <h2>优选域名管理</h2>
                <div style="display:flex; gap:10px; margin-bottom:15px;">
                    <input type="text" id="newD" placeholder="域名 (例如: cf.example.com)" style="flex:2; margin:0">
                    <input type="text" id="newR" placeholder="自定义备注" style="flex:1; margin:0">
                    <button class="nav-btn active" onclick="addDomain()">添加域名</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th onclick="sortDom('id')">ID ↕</th>
                                <th onclick="sortDom('domain')">域名 ↕</th>
                                <th onclick="sortDom('remark')">备注 ↕</th>
                                <th onclick="sortDom('created_at')">创建时间 ↕</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="domList"></tbody>
                    </table>
                </div>
                <div class="pagination-bar" id="domPager">
                    <div class="page-ctrl">
                        <select class="page-size" id="domSize" onchange="changeDomSize()">
                            <option value="5">5条/页</option>
                            <option value="10" selected>10条/页</option>
                            <option value="20">20条/页</option>
                            <option value="50">50条/页</option>
                        </select>
                    </div>
                    <div class="page-ctrl">
                        <button class="nav-btn small" onclick="changeDomPage(-1)">上一页</button>
                        <span class="page-info" id="domPageInfo">1 / 1</span>
                        <button class="nav-btn small" onclick="changeDomPage(1)">下一页</button>
                    </div>
                </div>
            </div>

            <div id="ips" class="card">
                <div class="auto-update-header">
                    <h2>IP 资源池管理</h2>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div class="auto-update-status">
                            <span class="status-indicator" id="globalStatusIndicator"></span>
                            <span id="globalStatusText">自动更新: 关闭</span>
                        </div>
                    </div>
                </div>
                
                <div class="switch-group">
                    <label class="switch-label">启用自动更新
                        <div class="switch">
                            <input type="checkbox" id="sw-global" checked>
                            <span class="slider"></span>
                        </div>
                    </label>
                    <label class="switch-label">HostMonit接口
                        <div class="switch">
                            <input type="checkbox" id="sw-hm" checked>
                            <span class="slider"></span>
                        </div>
                    </label>
                    <label class="switch-label">Vps789接口
                        <div class="switch">
                            <input type="checkbox" id="sw-v7" checked>
                            <span class="slider"></span>
                        </div>
                    </label>
                    <button class="nav-btn" onclick="saveAutoUpdateSettings()">保存设置</button>
                    <button class="nav-btn active" onclick="refreshIps()">立即更新</button>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th onclick="sortIp('ip')">IP 地址 ↕</th>
                                <th onclick="sortIp('ip_type')">类型 ↕</th>
                                <th onclick="sortIp('carrier')">运营商 ↕</th>
                                <th onclick="sortIp('created_at')">入库时间 ↕</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="ipList"></tbody>
                    </table>
                </div>
                <div class="pagination-bar" id="ipPager">
                    <div class="page-ctrl">
                        <select class="page-size" id="ipSize" onchange="changeIpSize()">
                            <option value="10">10条/页</option>
                            <option value="20" selected>20条/页</option>
                            <option value="50">50条/页</option>
                            <option value="100">100条/页</option>
                        </select>
                    </div>
                    <div class="page-ctrl">
                        <button class="nav-btn small" onclick="changeIpPage(-1)">上一页</button>
                        <span class="page-info" id="ipPageInfo">1 / 1</span>
                        <button class="nav-btn small" onclick="changeIpPage(1)">下一页</button>
                    </div>
                </div>
            </div>

            <div id="uuids" class="card">
                <h2>UUID 配置分组</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th onclick="sortUuid('uuid')">UUID ↕</th>
                                <th onclick="sortUuid('count')">包含节点数 ↕</th>
                                <th onclick="sortUuid('updated_at')">最近更新 ↕</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="uuidList"></tbody>
                    </table>
                </div>
                <div class="pagination-bar" id="uuidPager">
                    <div class="page-ctrl">
                        <select class="page-size" id="uuidSize" onchange="changeUuidSize()">
                            <option value="5">5条/页</option>
                            <option value="10" selected>10条/页</option>
                            <option value="20">20条/页</option>
                            <option value="50">50条/页</option>
                        </select>
                    </div>
                    <div class="page-ctrl">
                        <button class="nav-btn small" onclick="changeUuidPage(-1)">上一页</button>
                        <span class="page-info" id="uuidPageInfo">1 / 1</span>
                        <button class="nav-btn small" onclick="changeUuidPage(1)">下一页</button>
                    </div>
                </div>
            </div>

        </div>

        <footer class="footer">
            <p>Powered by <a href="https://www.yangzihome.space" target="_blank">YZFN</a> | <a href="https://www.yangzihome.space/security.html" target="_blank">安全声明</a></p>
        </footer>
    </div>

    <div class="modal-overlay" id="pwdModal">
        <div class="modal">
            <h3 style="margin-top:0; color:#3d474d">修改管理员密码</h3>
            <div style="margin-bottom:15px;"><input type="password" id="oldP" placeholder="当前旧密码"><input type="password" id="newP" placeholder="新密码"></div>
            <div style="display:flex; justify-content:flex-end; gap:10px;"><button class="nav-btn" onclick="document.getElementById('pwdModal').style.display='none'">取消</button><button class="nav-btn active" onclick="changePwd()">确认修改</button></div>
        </div>
    </div>

    <div class="modal-overlay" id="editDomModal">
        <div class="modal">
            <h3 style="margin-top:0; color:#3d474d">编辑域名</h3>
            <input type="hidden" id="editId">
            <div style="margin-bottom:15px;">
                <label style="display:block;margin-bottom:5px;font-size:0.9rem;color:#5a666d;">域名:</label><input type="text" id="editDomain">
                <label style="display:block;margin-bottom:5px;font-size:0.9rem;color:#5a666d;">备注:</label><input type="text" id="editRemark">
            </div>
            <div style="display:flex; justify-content:flex-end; gap:10px;"><button class="nav-btn" onclick="document.getElementById('editDomModal').style.display='none'">取消</button><button class="nav-btn active" onclick="updateDomain()">保存修改</button></div>
        </div>
    </div>

    <script>
        const token = localStorage.getItem('token');
        if (!token) window.location.href = '/login';

        // --- Tools ---
        function toast(m, type='info') { 
            const c = document.getElementById('toast-container'); 
            const d = document.createElement('div'); 
            d.className = 'toast'; 
            d.innerHTML = (type==='err'?'❌ ':'✅ ') + m; 
            c.appendChild(d); 
            setTimeout(()=>d.remove(), 4000); 
        }
        
        function fmtDate(ts) { 
            if (!ts) return '未知';
            const date = new Date(ts);
            return date.toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
        
        const api = async (path, method='GET', body) => {
            try {
                const res = await fetch('/api/'+path, { 
                    method, 
                    headers: {
                        'Authorization': 'Bearer ' + token, 
                        'Content-Type': 'application/json'
                    }, 
                    body: body ? JSON.stringify(body) : null 
                });
                if(res.status==401) return logout();
                const d = await res.json();
                if(d.error) throw new Error(d.error);
                return d;
            } catch(e) { toast(e.message, 'err'); return null; }
        };
        
        function logout() { 
            localStorage.removeItem('token'); 
            window.location.href='/login'; 
        }

        // --- State Management ---
        let domState = { page: 1, size: 10, total: 0, sort: 'id', order: 'desc' };
        let ipState = { page: 1, size: 20, total: 0, sort: 'created_at', order: 'desc' };
        let uuidState = { page: 1, size: 10, total: 0, sort: 'updated_at', order: 'desc' };
        let autoUpdateSettings = { global_enabled: false, hostmonit: true, vps789: true };

        // --- Init ---
        (async function init() {
            await loadStats();
            await loadAutoUpdateSettings();
            document.getElementById('loader').style.display = 'none';
            document.getElementById('app').style.display = 'flex';
        })();

        function switchTab(id, btn) {
            document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.nav-grid .nav-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            btn.classList.add('active');
            if(id === 'dash') loadStats();
            if(id === 'dom') loadDom();
            if(id === 'ips') loadIp();
            if(id === 'uuids') loadUuid();
        }

        async function loadStats() {
            const d = await api('stats');
            if(d) {
                document.getElementById('s-dom').innerText = d.domains;
                document.getElementById('s-ip').innerText = d.ips;
                document.getElementById('s-uuid').innerText = d.uuids;
                
                const statusText = d.autoUpdate === 1 ? '<span style="color:#10b981">已启用</span>' : '<span style="color:#ef4444">已关闭</span>';
                document.getElementById('autoUpdateStatus').innerHTML = statusText;
                
                if (d.lastExecuted > 0) {
                    document.getElementById('lastExecuted').innerText = fmtDate(d.lastExecuted);
                } else {
                    document.getElementById('lastExecuted').innerText = '从未执行';
                }
            }
        }

        async function loadAutoUpdateSettings() {
            const settings = await api('settings/auto-update');
            if (settings) {
                autoUpdateSettings = settings;
                
                // 更新UI开关状态
                document.getElementById('sw-global').checked = settings.global_enabled === 1;
                document.getElementById('sw-hm').checked = settings.hostmonit === 1;
                document.getElementById('sw-v7').checked = settings.vps789 === 1;
                
                // 更新状态指示器
                const indicator = document.getElementById('globalStatusIndicator');
                const statusText = document.getElementById('globalStatusText');
                
                if (settings.global_enabled === 1) {
                    indicator.className = 'status-indicator status-on';
                    statusText.textContent = '自动更新: 已启用';
                } else {
                    indicator.className = 'status-indicator status-off';
                    statusText.textContent = '自动更新: 已关闭';
                }
            }
        }

        async function saveAutoUpdateSettings() {
            const globalEnabled = document.getElementById('sw-global').checked;
            const hostmonitEnabled = document.getElementById('sw-hm').checked;
            const vps789Enabled = document.getElementById('sw-v7').checked;
            
            const res = await api('settings/auto-update', 'POST', {
                global_enabled: globalEnabled,
                hostmonit: hostmonitEnabled,
                vps789: vps789Enabled
            });
            
            if (res && res.success) {
                toast('自动更新设置已保存', 'success');
                await loadAutoUpdateSettings();
                await loadStats(); // 刷新状态显示
            }
        }

        // ======================= DOMAIN LOGIC =======================
        async function loadDom() {
            const q = \`domains?page=\${domState.page}&size=\${domState.size}&sort=\${domState.sort}&order=\${domState.order}\`;
            const d = await api(q);
            if(d && d.data) {
                let h = '';
                d.data.forEach(i => {
                    const domainSafe = (i.domain || '').replace(/"/g, '&quot;');
                    const remarkSafe = (i.remark || '').replace(/"/g, '&quot;');
                    h += \`<tr><td>\${i.id}</td><td>\${i.domain}</td><td>\${i.remark||'<span style="color:#ccc">无</span>'}</td><td>\${fmtDate(i.created_at)}</td><td><button class="nav-btn small" onclick="editD(\${i.id}, '\${domainSafe}', '\${remarkSafe}')">编辑</button> <button class="nav-btn danger small" onclick="delD(\${i.id})">删除</button></td></tr>\`;
                });
                document.getElementById('domList').innerHTML = h || '<tr><td colspan="5" style="text-align:center">无数据</td></tr>';
                domState.total = d.total;
                updatePager('dom', domState);
            }
        }
        
        async function addDomain() {
            const d = document.getElementById('newD').value, r = document.getElementById('newR').value;
            if(!d) return toast('域名不能为空', 'err');
            if(await api('domains', 'POST', {domain:d, remark:r})) {
                toast('添加成功'); 
                document.getElementById('newD').value=''; 
                document.getElementById('newR').value=''; 
                domState.page = 1; 
                loadDom();
            }
        }
        
        async function delD(id) { 
            if(confirm('确认删除?')) { 
                await api('domains', 'DELETE', {id}); 
                loadDom(); 
            } 
        }
        
        function editD(id, domain, remark) { 
            document.getElementById('editId').value = id; 
            document.getElementById('editDomain').value = domain; 
            document.getElementById('editRemark').value = remark; 
            document.getElementById('editDomModal').style.display = 'flex'; 
        }
        
        async function updateDomain() {
            const id = document.getElementById('editId').value; 
            const domain = document.getElementById('editDomain').value; 
            const remark = document.getElementById('editRemark').value;
            if(!domain) return toast('域名不能为空', 'err');
            if(await api('domains', 'PUT', { id, domain, remark })) { 
                toast('修改成功'); 
                document.getElementById('editDomModal').style.display = 'none'; 
                loadDom(); 
            }
        }
        
        function changeDomPage(d) { changePage('dom', d, domState, loadDom); }
        function changeDomSize() { changeSize('dom', domState, loadDom); }
        function sortDom(f) { changeSort(f, domState, loadDom); }

        // ======================= IP LOGIC =======================
        async function loadIp() {
            const q = \`ips?page=\${ipState.page}&size=\${ipState.size}&sort=\${ipState.sort}&order=\${ipState.order}\`;
            const d = await api(q);
            if(d && d.data) {
                let h = '';
                d.data.forEach(i => h += \`<tr><td>\${i.ip}</td><td>\${i.ip_type}</td><td>\${i.carrier}</td><td>\${fmtDate(i.created_at)}</td><td><button class="nav-btn danger small" onclick="delI('\${i.ip}')">删除</button></td></tr>\`);
                document.getElementById('ipList').innerHTML = h || '<tr><td colspan="5" style="text-align:center">无数据</td></tr>';
                ipState.total = d.total;
                updatePager('ip', ipState);
            }
        }
        
        async function refreshIps() {
            const hm = document.getElementById('sw-hm').checked; 
            const v7 = document.getElementById('sw-v7').checked;
            toast('IP更新任务已开始...', 'info');
            const res = await api('ips/refresh', 'POST', { 
                hostmonit: hm, 
                vps789: v7 
            });
            if(res && res.success) { 
                toast(\`更新完成: \${res.message}\`); 
                ipState.page = 1; 
                loadIp(); 
                loadStats(); 
            } else if (res) { 
                toast(\`更新失败: \${res.message}\`, 'err'); 
            }
        }
        
        async function delI(ip) { 
            if(confirm('删除此 IP?')) { 
                await api('ips', 'DELETE', {ip}); 
                loadIp(); 
            } 
        }
        
        function changeIpPage(d) { changePage('ip', d, ipState, loadIp); }
        function changeIpSize() { changeSize('ip', ipState, loadIp); }
        function sortIp(f) { changeSort(f, ipState, loadIp); }

        // ======================= UUID LOGIC =======================
        async function loadUuid() {
            const q = \`uuids?page=\${uuidState.page}&size=\${uuidState.size}&sort=\${uuidState.sort}&order=\${uuidState.order}\`;
            const d = await api(q);
            if(d && d.data) {
                let h = '';
                d.data.forEach(i => h += \`<tr><td>\${i.uuid}</td><td>\${i.count} 个配置</td><td>\${fmtDate(i.updated_at)}</td><td><button class="nav-btn danger small" onclick="delU('\${i.uuid}')">删除整组</button></td></tr>\`);
                document.getElementById('uuidList').innerHTML = h || '<tr><td colspan="4" style="text-align:center">无数据</td></tr>';
                uuidState.total = d.total;
                updatePager('uuid', uuidState);
            }
        }
        
        async function delU(u) { 
            if(confirm('确认删除?')) { 
                await api('uuids', 'DELETE', {uuid:u}); 
                loadUuid(); 
            } 
        }
        
        function changeUuidPage(d) { changePage('uuid', d, uuidState, loadUuid); }
        function changeUuidSize() { changeSize('uuid', uuidState, loadUuid); }
        function sortUuid(f) { changeSort(f, uuidState, loadUuid); }

        // ======================= GENERIC HELPERS =======================
        function updatePager(p, s) {
            const max = Math.ceil(s.total / s.size) || 1;
            document.getElementById(p+'PageInfo').innerText = \`\${s.page} / \${max} (共\${s.total}条)\`;
            document.getElementById(p+'Size').value = s.size;
        }
        
        function changePage(p, delta, state, cb) {
            const max = Math.ceil(state.total / state.size) || 1;
            const n = state.page + delta;
            if(n > 0 && n <= max) { state.page = n; cb(); }
        }
        
        function changeSize(p, state, cb) {
            state.size = parseInt(document.getElementById(p+'Size').value);
            state.page = 1; 
            cb();
        }
        
        function changeSort(field, state, cb) {
            if(state.sort === field) { 
                state.order = state.order === 'asc' ? 'desc' : 'asc'; 
            } else { 
                state.sort = field; 
                state.order = 'desc'; 
            }
            cb();
        }

        // --- 密码修改 ---
        function openPwdModal() { document.getElementById('pwdModal').style.display='flex'; }
        
        async function changePwd() {
            const o = document.getElementById('oldP').value, n = document.getElementById('newP').value;
            if(!o || !n) return toast('请填写完整', 'err');
            const res = await api('change-password', 'POST', {oldPassword:o, newPassword:n});
            if(res && res.success) { alert('密码修改成功，请重新登录'); logout(); }
        }
    </script>
</body>
</html>
`;

// 添加一个简单的数据库初始化函数（如果需要）
async function initializeDatabase(env) {
    try {
        // 创建自动更新设置表
        await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS auto_update_settings (
                source TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                updated_at INTEGER
            )
        `).run();
        
        console.log("数据库表初始化完成");
    } catch (e) {
        console.error("数据库初始化失败:", e);
    }
}

// 在fetch或scheduled的开始调用初始化（根据实际需要）
// 注意：由于Cloudflare Workers限制，建议在生产环境中手动执行SQL创建表
