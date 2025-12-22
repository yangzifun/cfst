/* =================================================================
 * Cloudflare Worker: YZFN Configuration Management with MFA
 * ================================================================= */

// =================================================================
//  1. 常量定义
// =================================================================
const DEFAULT_JWT_SECRET = 'your-default-jwt-secret-change-this';

// =================================================================
//  2. 工具函数
// =================================================================

// 密码哈希
async function hashPassword(password) {
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// JWT签名
async function signJwt(payload, secret = DEFAULT_JWT_SECRET) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

// JWT验证
async function verifyJwt(token, secret = DEFAULT_JWT_SECRET) {
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

// JSON响应
function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { 
        status, 
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-cache, no-store'
        } 
    });
}

// =================================================================
//  3. TOTP实现
// =================================================================

class TOTP {
    // 生成随机密钥
    static generateSecret() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let secret = '';
        for (let i = 0; i < 20; i++) {
            secret += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return secret;
    }

    // 生成OTP验证码
    static generateOTP(secret, window = 0) {
        const time = Math.floor(Date.now() / 30000) + window;
        return this.generateOTPWithTime(secret, time);
    }

    // 使用指定时间生成OTP
    static generateOTPWithTime(secret, time) {
        const key = this.base32ToBytes(secret);
        const timeBuffer = new ArrayBuffer(8);
        const timeView = new DataView(timeBuffer);
        timeView.setUint32(0, Math.floor(time / 0x100000000));
        timeView.setUint32(4, time % 0x100000000);
        
        const keyObj = crypto.subtle.importKey('raw', new Uint8Array(key), 
            { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
        
        return keyObj.then(k => {
            return crypto.subtle.sign('HMAC', k, timeBuffer);
        }).then(signature => {
            const sigArray = new Uint8Array(signature);
            const offset = sigArray[sigArray.length - 1] & 0xf;
            
            const binary = ((sigArray[offset] & 0x7f) << 24) |
                          ((sigArray[offset + 1] & 0xff) << 16) |
                          ((sigArray[offset + 2] & 0xff) << 8) |
                          (sigArray[offset + 3] & 0xff);
            
            const otp = binary % 1000000;
            return otp.toString().padStart(6, '0');
        });
    }

    // Base32转换
    static base32ToBytes(base32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const bytes = [];
        let bits = 0;
        let buffer = 0;
        
        for (let i = 0; i < base32.length; i++) {
            const char = base32.charAt(i);
            const value = chars.indexOf(char);
            if (value === -1) continue;
            
            buffer = (buffer << 5) | value;
            bits += 5;
            
            while (bits >= 8) {
                bits -= 8;
                bytes.push((buffer >> bits) & 0xff);
                buffer &= (1 << bits) - 1;
            }
        }
        
        return bytes;
    }

    // 验证OTP码
    static async verify(secret, code, window = 1) {
        for (let i = -window; i <= window; i++) {
            const genCode = await this.generateOTP(secret, i);
            if (genCode === code) return true;
        }
        return false;
    }

    // 生成二维码URL
    static generateOTPAuthURL(username, secret, issuer = 'YZFN Admin') {
        const encodedIssuer = encodeURIComponent(issuer);
        const encodedUsername = encodeURIComponent(username);
        return `otpauth://totp/${encodedIssuer}:${encodedUsername}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
    }
}

// =================================================================
//  4. IP获取函数
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
    } catch (e) { return []; }
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
    } catch (e) { return []; }
}

async function runIpUpdateTask(env, sources = null) {
    console.log('开始IP更新任务...');
    
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
            } else {
                sources = { hostmonit: true, vps789: true };
            }
        } catch (e) {
            sources = { hostmonit: true, vps789: true };
        }
    }

    const tasks = [];
    if (sources.hostmonit !== false) tasks.push(fetchIpsFromHostMonit());
    if (sources.vps789 !== false) tasks.push(fetchIpsFromVps789());

    if (tasks.length === 0) {
        console.log("没有启用的API源");
        return { success: false, message: "没有启用的API源" };
    }

    const results = await Promise.allSettled(tasks);
    const allIps = results
        .filter(r => r.status === 'fulfilled')
        .map(r => r.value)
        .flat();

    const uniqueMap = new Map();
    allIps.forEach(i => { if (i && i.ip) uniqueMap.set(i.ip, i); });
    const uniqueIps = Array.from(uniqueMap.values());

    if (uniqueIps.length === 0) {
        return { success: false, message: "未能获取到任何有效IP", count: 0 };
    }

    try {
        const globalSetting = await env.DB.prepare(
            'SELECT enabled FROM auto_update_settings WHERE source = ?'
        ).bind('global_enabled').first();
        
        if (globalSetting && globalSetting.enabled === 0) {
            return { 
                success: true, 
                count: uniqueIps.length, 
                message: `获取到 ${uniqueIps.length} 个IP，但自动更新已关闭`,
                data: uniqueIps.slice(0, 10)
            };
        }

        await env.DB.prepare('DELETE FROM cfips').run();
        
        const stmts = uniqueIps.map(i =>
            env.DB.prepare('INSERT INTO cfips (ip, ip_type, carrier, created_at) VALUES (?, ?, ?, ?)')
                .bind(i.ip, i.ip_type, i.carrier, Date.now())
        );
        
        const BATCH_SIZE = 50;
        for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
            const batch = stmts.slice(i, i + BATCH_SIZE);
            await env.DB.batch(batch);
        }
        
        await env.DB.prepare(
            'INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)'
        ).bind('last_executed', 1, Date.now()).run();
        
        console.log(`IP更新完成: ${uniqueIps.length}条记录`);
        return { 
            success: true, 
            count: uniqueIps.length, 
            message: `成功更新 ${uniqueIps.length} 个 IP`,
            timestamp: Date.now()
        };
        
    } catch (e) {
        return { success: false, message: "数据库错误: " + e.message };
    }
}

// =================================================================
//  5. API处理函数
// =================================================================

async function handleLogin(req, env) {
    try {
        const { username, password, totp_code, step } = await req.json();
        
        const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE username = ?'
        ).bind(username).first();
        
        if (!user || (await hashPassword(password)) !== user.password_hash) {
            return jsonResponse({ error: '用户名或密码错误' }, 401);
        }
        
        const requiresMFA = user.mfa_enabled === 1;
        
        if (!step) {
            if (!requiresMFA) {
                const token = await signJwt(
                    { 
                        sub: user.username, 
                        exp: Date.now() + 86400000,
                        requires_mfa: false
                    }, 
                    env.JWT_SECRET || DEFAULT_JWT_SECRET
                );
                return jsonResponse({ token, requires_mfa: false });
            } else {
                return jsonResponse({ 
                    requires_mfa: true, 
                    username: user.username,
                    step: 'totp_required'
                });
            }
        }
        
        if (step === 'verify_totp' && requiresMFA) {
            if (!totp_code) {
                return jsonResponse({ error: '请输入验证码' }, 400);
            }
            
            if (!user.mfa_secret) {
                return jsonResponse({ error: 'MFA未设置' }, 400);
            }
            
            const isValid = await TOTP.verify(user.mfa_secret, totp_code, 1);
            if (!isValid) {
                return jsonResponse({ error: '验证码无效或已过期' }, 401);
            }
            
            await env.DB.prepare(
                'UPDATE admin_users SET last_mfa_login = ? WHERE username = ?'
            ).bind(Date.now(), user.username).run();
            
            const token = await signJwt(
                { 
                    sub: user.username, 
                    exp: Date.now() + 86400000,
                    requires_mfa: true,
                    mfa_verified: true
                }, 
                env.JWT_SECRET || DEFAULT_JWT_SECRET
            );
            
            return jsonResponse({ 
                token, 
                requires_mfa: true,
                message: 'MFA验证成功'
            });
        }
        
        return jsonResponse({ error: '无效的登录步骤' }, 400);
    } catch (e) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleMfaInit(req, env) {
    try {
        const { username, password } = await req.json();
        
        const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE username = ?'
        ).bind(username).first();
        
        if (!user || (await hashPassword(password)) !== user.password_hash) {
            return jsonResponse({ error: '用户名或密码错误' }, 401);
        }
        
        if (user.mfa_enabled === 1) {
            return jsonResponse({ error: 'MFA已启用' }, 400);
        }
        
        const newSecret = TOTP.generateSecret();
        const otpauth_url = TOTP.generateOTPAuthURL(username, newSecret);
        
        return jsonResponse({
            success: true,
            secret: newSecret,
            otpauth_url: otpauth_url,
            otpauth_url_encoded: encodeURIComponent(otpauth_url),
            qr_url: `https://qrcode.api.yangzifun.org/?data=${encodeURIComponent(otpauth_url)}&size=200`,
            message: '请使用身份验证器App手动输入密钥'
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleMfaVerifyFirst(req, env) {
    try {
        const { username, totp_code, secret } = await req.json();
        
        if (!totp_code || !secret) {
            return jsonResponse({ error: '请提供验证码和密钥' }, 400);
        }
        
        const isValid = await TOTP.verify(secret, totp_code, 1);
        if (!isValid) {
            return jsonResponse({ error: '验证码无效或已过期' }, 400);
        }
        
        const backupCodes = Array.from({ length: 10 }, () => 
            Math.random().toString(36).substring(2, 10).toUpperCase()
        );
        
        await env.DB.prepare(
            'UPDATE admin_users SET mfa_enabled = 1, mfa_secret = ? WHERE username = ?'
        ).bind(secret, username).run();
        
        const stmts = backupCodes.map(code =>
            env.DB.prepare(
                'INSERT INTO mfa_backup_codes (username, code, created_at, used) VALUES (?, ?, ?, 0)'
            ).bind(username, code, Date.now())
        );
        
        if (stmts.length > 0) {
            await env.DB.batch(stmts);
        }
        
        return jsonResponse({
            success: true,
            message: 'MFA已成功启用',
            backup_codes: backupCodes,
            important: '请妥善保管备份码'
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleMfaLoginWithBackup(req, env) {
    try {
        const { username, password, backup_code } = await req.json();
        
        const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE username = ? AND mfa_enabled = 1'
        ).bind(username).first();
        
        if (!user || (await hashPassword(password)) !== user.password_hash) {
            return jsonResponse({ error: '用户名或密码错误' }, 401);
        }
        
        const backupRecord = await env.DB.prepare(
            'SELECT * FROM mfa_backup_codes WHERE username = ? AND code = ? AND used = 0'
        ).bind(username, backup_code.trim().toUpperCase()).first();
        
        if (!backupRecord) {
            return jsonResponse({ error: '备份码无效或已使用' }, 401);
        }
        
        await env.DB.prepare(
            'UPDATE mfa_backup_codes SET used = 1, used_at = ? WHERE id = ?'
        ).bind(Date.now(), backupRecord.id).run();
        
        await env.DB.prepare(
            'UPDATE admin_users SET last_backup_login = ? WHERE username = ?'
        ).bind(Date.now(), username).run();
        
        const token = await signJwt(
            { 
                sub: user.username, 
                exp: Date.now() + 86400000,
                requires_mfa: true,
                mfa_verified: true,
                via_backup_code: true
            }, 
            env.JWT_SECRET || DEFAULT_JWT_SECRET
        );
        
        const remaining = await env.DB.prepare(
            'SELECT COUNT(*) as count FROM mfa_backup_codes WHERE username = ? AND used = 0'
        ).bind(username).first('count') || 0;
        
        return jsonResponse({
            token,
            message: '使用备份码登录成功',
            backup_codes_remaining: remaining
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleChangePassword(req, env, currentUser) {
    try {
        const { oldPassword, newPassword } = await req.json();
        
        const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE username = ?'
        ).bind(currentUser).first();
        
        if (!user || (await hashPassword(oldPassword)) !== user.password_hash) {
            return jsonResponse({ error: '旧密码错误' }, 403);
        }
        
        await env.DB.prepare(
            'UPDATE admin_users SET password_hash = ? WHERE username = ?'
        ).bind(await hashPassword(newPassword), currentUser).run();
        
        return jsonResponse({ 
            success: true,
            message: '密码修改成功'
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleMfaStatus(req, env, currentUser) {
    try {
        const user = await env.DB.prepare(
            'SELECT mfa_enabled, last_mfa_login, last_backup_login FROM admin_users WHERE username = ?'
        ).bind(currentUser).first();
        
        const backupCodesCount = await env.DB.prepare(
            'SELECT COUNT(*) as count FROM mfa_backup_codes WHERE username = ? AND used = 0'
        ).bind(currentUser).first('count') || 0;
        
        return jsonResponse({
            mfa_enabled: user.mfa_enabled === 1,
            last_mfa_login: user.last_mfa_login,
            last_backup_login: user.last_backup_login,
            backup_codes_remaining: backupCodesCount
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleMfaDisable(req, env, currentUser) {
    try {
        const { password } = await req.json();
        
        const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE username = ?'
        ).bind(currentUser).first();
        
        if ((await hashPassword(password)) !== user.password_hash) {
            return jsonResponse({ error: '密码错误' }, 401);
        }
        
        await env.DB.prepare(
            'UPDATE admin_users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?'
        ).bind(currentUser).run();
        
        await env.DB.prepare(
            'DELETE FROM mfa_backup_codes WHERE username = ?'
        ).bind(currentUser).run();
        
        return jsonResponse({
            success: true,
            message: 'MFA已禁用'
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleMfaRegenerateBackupCodes(req, env, currentUser) {
    try {
        const { password } = await req.json();
        
        const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE username = ?'
        ).bind(currentUser).first();
        
        if ((await hashPassword(password)) !== user.password_hash) {
            return jsonResponse({ error: '密码错误' }, 401);
        }
        
        if (user.mfa_enabled !== 1) {
            return jsonResponse({ error: 'MFA未启用' }, 400);
        }
        
        const newBackupCodes = Array.from({ length: 10 }, () => 
            Math.random().toString(36).substring(2, 10).toUpperCase()
        );
        
        await env.DB.prepare(
            'DELETE FROM mfa_backup_codes WHERE username = ?'
        ).bind(currentUser).run();
        
        const stmts = newBackupCodes.map(code =>
            env.DB.prepare(
                'INSERT INTO mfa_backup_codes (username, code, created_at, used) VALUES (?, ?, ?, 0)'
            ).bind(currentUser, code, Date.now())
        );
        
        if (stmts.length > 0) {
            await env.DB.batch(stmts);
        }
        
        return jsonResponse({
            success: true,
            backup_codes: newBackupCodes,
            message: '备份码已重新生成'
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleGetAutoUpdateSettings(req, env) {
    try {
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
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleSetAutoUpdateSettings(req, env) {
    try {
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
        return jsonResponse({ 
            success: true,
            message: '自动更新设置已保存'
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleGetStats(req, env) {
    try {
        const domains = await env.DB.prepare('SELECT COUNT(*) as c FROM cf_domains').first('c');
        const ips = await env.DB.prepare('SELECT COUNT(*) as c FROM cfips').first('c');
        const uuids = await env.DB.prepare('SELECT COUNT(DISTINCT uuid) as c FROM configs').first('c');
        
        const enabled = await env.DB.prepare(
            'SELECT enabled FROM auto_update_settings WHERE source = ?'
        ).bind('global_enabled').first('enabled');
        
        const lastExec = await env.DB.prepare(
            'SELECT updated_at FROM auto_update_settings WHERE source = ?'
        ).bind('last_executed').first('updated_at');
        
        return jsonResponse({ 
            domains: domains || 0, 
            ips: ips || 0, 
            uuids: uuids || 0,
            autoUpdate: enabled || 0,
            lastExecuted: lastExec || 0
        });
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleDomains(req, env, method) {
    try {
        const url = new URL(req.url);
        
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

            return jsonResponse({ 
                total: total || 0, 
                data: results || [], 
                page, 
                size 
            });
        }
        
        if (method === 'POST') {
            const { domain, remark } = await req.json();
            if(!domain) return jsonResponse({error:'域名不能为空'}, 400);
            
            await env.DB.prepare(
                'INSERT INTO cf_domains (domain, remark, created_at) VALUES (?, ?, ?)'
            ).bind(domain, remark || '', Date.now()).run();
            
            return jsonResponse({ 
                success: true,
                message: '域名添加成功'
            });
        }
        
        if (method === 'PUT') {
            const { id, domain, remark } = await req.json();
            if(!id || !domain) return jsonResponse({error:'ID和域名不能为空'}, 400);
            
            await env.DB.prepare(
                'UPDATE cf_domains SET domain = ?, remark = ? WHERE id = ?'
            ).bind(domain, remark || '', id).run();
            
            return jsonResponse({ 
                success: true,
                message: '域名更新成功'
            });
        }
        
        if (method === 'DELETE') {
            const { id } = await req.json();
            if (!id) return jsonResponse({error:'ID不能为空'}, 400);
            
            await env.DB.prepare('DELETE FROM cf_domains WHERE id = ?').bind(id).run();
            return jsonResponse({ 
                success: true,
                message: '域名删除成功'
            });
        }
        
        return jsonResponse({ error: '不支持的请求方法' }, 405);
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleIps(req, env, method) {
    try {
        const url = new URL(req.url);
        
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

            return jsonResponse({ 
                total: total || 0, 
                data: results || [], 
                page, 
                size 
            });
        }
        
        if (method === 'DELETE') {
            const { ip } = await req.json();
            if (!ip) return jsonResponse({error:'IP不能为空'}, 400);
            
            await env.DB.prepare('DELETE FROM cfips WHERE ip = ?').bind(ip).run();
            return jsonResponse({ 
                success: true,
                message: 'IP删除成功'
            });
        }
        
        return jsonResponse({ error: '不支持的请求方法' }, 405);
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleIpsRefresh(req, env) {
    try {
        const body = await req.json().catch(() => ({}));
        const res = await runIpUpdateTask(env, body);
        return jsonResponse(res);
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

async function handleUuids(req, env, method) {
    try {
        const url = new URL(req.url);
        
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

            return jsonResponse({ 
                total: total || 0, 
                data: results || [], 
                page, 
                size 
            });
        }
        
        if (method === 'DELETE') {
            const { uuid } = await req.json();
            if (!uuid) return jsonResponse({error:'UUID不能为空'}, 400);
            
            await env.DB.prepare('DELETE FROM configs WHERE uuid = ?').bind(uuid).run();
            return jsonResponse({ 
                success: true,
                message: 'UUID组删除成功'
            });
        }
        
        return jsonResponse({ error: '不支持的请求方法' }, 405);
    } catch (error) {
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

// =================================================================
//  6. 主API路由处理
// =================================================================

async function handleApi(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    try {
        // 无需认证的API
        if (path === '/api/login' && method === 'POST') {
            return await handleLogin(req, env);
        }
        
        if (path === '/api/mfa/init' && method === 'POST') {
            return await handleMfaInit(req, env);
        }
        
        if (path === '/api/mfa/verify-first' && method === 'POST') {
            return await handleMfaVerifyFirst(req, env);
        }
        
        if (path === '/api/mfa/login-with-backup' && method === 'POST') {
            return await handleMfaLoginWithBackup(req, env);
        }
        
        // 需要JWT认证的API
        const authHeader = req.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return jsonResponse({ error: '未授权，请重新登录' }, 401);
        }
        
        const token = authHeader.split(' ')[1];
        const payload = await verifyJwt(token, env.JWT_SECRET || DEFAULT_JWT_SECRET);
        
        if (!payload) {
            return jsonResponse({ error: 'Token 无效或已过期' }, 401);
        }
        
        const currentUser = payload.sub;
        
        // 认证后的API
        if (path === '/api/change-password' && method === 'POST') {
            return await handleChangePassword(req, env, currentUser);
        }
        
        if (path === '/api/mfa/status' && method === 'GET') {
            return await handleMfaStatus(req, env, currentUser);
        }
        
        if (path === '/api/mfa/disable' && method === 'POST') {
            return await handleMfaDisable(req, env, currentUser);
        }
        
        if (path === '/api/mfa/backup-codes/regenerate' && method === 'POST') {
            return await handleMfaRegenerateBackupCodes(req, env, currentUser);
        }
        
        if (path === '/api/settings/auto-update' && method === 'GET') {
            return await handleGetAutoUpdateSettings(req, env);
        }
        
        if (path === '/api/settings/auto-update' && method === 'POST') {
            return await handleSetAutoUpdateSettings(req, env);
        }
        
        if (path === '/api/stats' && method === 'GET') {
            return await handleGetStats(req, env);
        }
        
        if (path === '/api/domains' && ['GET', 'POST', 'PUT', 'DELETE'].includes(method)) {
            return await handleDomains(req, env, method);
        }
        
        if (path === '/api/ips' && ['GET', 'DELETE'].includes(method)) {
            return await handleIps(req, env, method);
        }
        
        if (path === '/api/ips/refresh' && method === 'POST') {
            return await handleIpsRefresh(req, env);
        }
        
        if (path === '/api/uuids' && ['GET', 'DELETE'].includes(method)) {
            return await handleUuids(req, env, method);
        }
        
        return jsonResponse({ error: 'API端点不存在' }, 404);
        
    } catch (error) {
        console.error('API处理错误:', error);
        return jsonResponse({ error: '服务器内部错误: ' + error.message }, 500);
    }
}

// =================================================================
//  7. HTML模板
// =================================================================

const globalCss = `
/* 全局CSS样式 */
html { font-size: 14px; }
body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { width: 100%; min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 20px 20px 40px; box-sizing: border-box; }
.content-group { width: 100%; max-width: 1000px; text-align: center; margin-top: 20px; }
.profile-name { font-size: 2rem; color: #3d474d; margin-bottom: 5px; font-weight: bold;}
.profile-quote { color: #89949B; margin-bottom: 10px; min-height: 1em; }
.top-bar { width: 100%; max-width: 1000px; display: flex; justify-content: space-between; margin-bottom: 20px; align-items: center; padding: 0 5px; box-sizing: border-box; }
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
input[type="text"], input[type="password"], input[type="number"] { width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px; background: #fff; font-size: 0.9rem; box-sizing: border-box; margin-bottom: 10px; }
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
.status-warning { background-color: #f59e0b; }
.mfa-status-badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 500; gap: 6px; }
.mfa-active { background-color: #d1fae5; color: #065f46; }
.mfa-inactive { background-color: #fee2e2; color: #9f1239; }
.qr-code-container { text-align: center; margin: 20px 0; padding: 15px; background: #f9fafb; border-radius: 8px; border: 1px solid #e5e7eb; }
.qr-instructions { font-size: 0.9rem; color: #6b7280; margin-top: 15px; line-height: 1.5; }
.backup-codes-box { background: #f3f4f6; border: 1px dashed #d1d5db; padding: 15px; border-radius: 6px; margin: 15px 0; font-family: monospace; text-align: center; line-height: 2; }
.backup-code { display: inline-block; margin: 5px; padding: 5px 10px; background: white; border: 1px solid #e5e7eb; border-radius: 4px; font-weight: bold; }
.security-step { background: #f0f9ff; border: 1px solid #bae6fd; padding: 15px; border-radius: 8px; margin: 15px 0; }
.security-step h4 { color: #0369a1; margin-top: 0; }
.security-step ol, .security-step ul { padding-left: 20px; }
#toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast { padding: 12px 18px; border-radius: 4px; border: 2px solid #89949B; background: #fff; color: #3d474d; font-weight: 500; font-size: 0.9rem; box-shadow: 0 4px 12px rgba(0,0,0,0.1); animation: slideIn 0.3s forwards, fadeOut 0.5s 3.5s forwards; }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
@keyframes fadeOut { to { opacity: 0; transform: translateX(100%); } }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100; display: none; align-items: center; justify-content: center; }
.modal { background: #fff; width: 90%; max-width: 450px; padding: 25px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto; }
.stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
.stat-box { background: #e8ebed; padding: 20px; border-radius: 4px; text-align: center; }
.stat-num { font-size: 2rem; color: #5a666d; font-weight: bold; display: block; }
.stat-label { font-size: 0.85rem; color: #89949B; }
.last-update-info { margin-top: 10px; font-size: 0.85rem; color: #3d474d; }
.security-section { background: #f9fafb; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 0 8px 8px 0; }
.security-section h3 { margin-top: 0; color: #1e40af; }
.mfa-container { max-width: 600px; margin: 0 auto; }
.secret-display { background: #1f2937; color: #fbbf24; padding: 15px; border-radius: 6px; font-family: monospace; text-align: center; margin: 15px 0; font-size: 1.1rem; letter-spacing: 1px; }
.copy-btn { margin-left: 10px; padding: 5px 10px; background: #4b5563; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8rem; }
.login-box { width: 100%; max-width: 400px; padding: 40px 30px; border: 2px solid #89949B; border-radius: 8px; background: #fff; text-align: center; margin: auto; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); }
.login-step { display: block; }
.totp-input-container { display: flex; gap: 10px; margin: 20px 0; }
.totp-input { flex: 1; text-align: center; font-size: 1.5rem; letter-spacing: 10px; font-weight: bold; }
.backup-link { display: block; margin-top: 15px; font-size: 0.9rem; color: #6b7280; text-decoration: underline; cursor: pointer; }
`;

const loginHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico">
    <title>优选配置管理后台 - 登录</title>
    <style>
        ${globalCss}
        body { display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; min-height: 500px; background: #f9fafb; }
    </style>
</head>
<body>
    <div id="toast-container"></div>
    
    <div class="login-box" id="passwordStep">
        <h2 class="profile-name">优选配置管理后台</h2>
        <p class="profile-quote" id="loginStatus">请先验证身份</p>
        <div id="msg" style="color:#ef4444; font-size:0.9rem; margin-bottom:10px; display:none;"></div>
        
        <form id="loginForm" onsubmit="event.preventDefault(); doLogin();">
            <input type="text" id="username" placeholder="管理员账号" required autocomplete="username">
            <input type="password" id="password" placeholder="访问密码" required autocomplete="current-password">
            <button type="submit" id="loginBtn" class="nav-btn active" style="width:100%; margin-top:15px;">登 录</button>
        </form>
        
        <div style="margin-top: 15px; font-size: 0.8rem; color: #9ca3af;">
            首次登录请确保网络连接正常
        </div>
    </div>

    <div class="login-box" id="totpStep" style="display: none;">
        <h2 class="profile-name">双重验证</h2>
        <p class="profile-quote" id="mfaUsername"></p>
        
        <div style="text-align: center; margin: 20px 0;">
            <div style="font-size: 0.95rem; color: #4b5563; margin-bottom: 15px;">
                请输入您的6位验证码
            </div>
            
            <div class="totp-input-container">
                <input type="text" id="totpCode" maxlength="6" class="totp-input" 
                       pattern="[0-9]{6}" inputmode="numeric" 
                       placeholder="000000" required autocomplete="one-time-code">
            </div>
            
            <div style="color: #6b7280; font-size: 0.85rem; margin-bottom: 15px;">
                请从身份验证器App获取验证码
            </div>
            
            <div style="display: flex; gap: 10px;">
                <button type="button" class="nav-btn" onclick="goBackToPassword()" style="flex: 1;">返回</button>
                <button type="button" class="nav-btn active" onclick="verifyTOTP()" id="verifyTOTPBtn" style="flex: 2;">验证</button>
            </div>
        </div>
        
        <a class="backup-link" onclick="verifyTOTP()" id="verifyTOTPBtn" style="flex: 2;">验证</button>
            </div>
        </div>
        
        <a class="backup-link" onclick="showBackupLogin()">使用备份码登录</a>
    </div>

    <div class="login-box" id="backupStep" style="display: none;">
        <h2 class="profile-name">备份码登录</h2>
        <p class="profile-quote">请输入8位备份码</p>
        
        <input type="text" id="backupUsername" style="display:none;">
        <input type="password" id="backupPassword" style="display:none;">
        
        <div style="text-align: left; margin: 15px 0;">
            <label style="display:block; margin-bottom:5px; font-size:0.9rem; color:#4b5563;">备份码:</label>
            <input type="text" id="backupCode" placeholder="例如：A1B2C3D4" maxlength="8" style="text-transform: uppercase;" required>
        </div>
        
        <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="button" class="nav-btn" onclick="cancelBackupLogin()" style="flex: 1;">取消</button>
            <button type="button" class="nav-btn active" onclick="verifyBackupCode()" id="verifyBackupBtn" style="flex: 2;">验证备份码</button>
        </div>
        
        <div style="margin-top: 15px; font-size: 0.8rem; color: #6b7280; text-align: left;">
            <p>• 备份码为一次性使用，用后失效</p>
            <p>• 请确保备份码准确无误</p>
        </div>
    </div>

    <footer class="footer" style="border:none; width:auto; margin-top: 30px;">
        <p>Powered by <a href="https://www.yangzihome.space" target="_blank">YZFN</a></p>
    </footer>
    
    <script>
        function toast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.innerHTML = (type === 'error' ? '❌ ' : '✅ ') + message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 4000);
        }
        
        async function doLogin() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const btn = document.getElementById('loginBtn');
            const msg = document.getElementById('msg');
            
            if (!username || !password) {
                msg.innerText = '请输入用户名和密码';
                msg.style.display = 'block';
                return;
            }
            
            btn.disabled = true;
            btn.innerText = '验证中...';
            msg.style.display = 'none';
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username, 
                        password 
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    if (data.requires_mfa) {
                        sessionStorage.setItem('mfa_username', username);
                        sessionStorage.setItem('mfa_password', password);
                        
                        document.getElementById('passwordStep').style.display = 'none';
                        document.getElementById('totpStep').style.display = 'block';
                        document.getElementById('mfaUsername').innerText = username;
                        document.getElementById('msg').style.display = 'none';
                        
                        setTimeout(() => document.getElementById('totpCode').focus(), 100);
                    } else {
                        localStorage.setItem('token', data.token);
                        localStorage.setItem('mfa_enabled', 'false');
                        window.location.href = '/';
                    }
                } else {
                    msg.innerText = data.error || '登录失败';
                    msg.style.display = 'block';
                }
            } catch (error) {
                msg.innerText = '连接服务器失败';
                msg.style.display = 'block';
            } finally {
                btn.disabled = false;
                btn.innerText = '登 录';
            }
        }
        
        function goBackToPassword() {
            document.getElementById('passwordStep').style.display = 'block';
            document.getElementById('totpStep').style.display = 'none';
            document.getElementById('backupStep').style.display = 'none';
            document.getElementById('msg').style.display = 'none';
            document.getElementById('password').value = '';
            document.getElementById('password').focus();
        }
        
        async function verifyTOTP() {
            const totpCode = document.getElementById('totpCode').value;
            const username = sessionStorage.getItem('mfa_username');
            const password = sessionStorage.getItem('mfa_password');
            const btn = document.getElementById('verifyTOTPBtn');
            
            if (!totpCode || totpCode.length !== 6) {
                toast('请输入6位验证码', 'error');
                return;
            }
            
            btn.disabled = true;
            btn.innerText = '验证中...';
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username,
                        password,
                        totp_code: totpCode,
                        step: 'verify_totp'
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('mfa_enabled', 'true');
                    sessionStorage.removeItem('mfa_username');
                    sessionStorage.removeItem('mfa_password');
                    toast('双重验证成功');
                    setTimeout(() => window.location.href = '/', 1000);
                } else {
                    toast(data.error || '验证失败', 'error');
                    document.getElementById('totpCode').value = '';
                    document.getElementById('totpCode').focus();
                }
            } catch (error) {
                toast('验证失败，请重试', 'error');
            } finally {
                btn.disabled = false;
                btn.innerText = '验证';
            }
        }
        
        function showBackupLogin() {
            const username = sessionStorage.getItem('mfa_username');
            const password = sessionStorage.getItem('mfa_password');
            
            if (!username || !password) {
                toast('会话信息丢失，请重新登录', 'error');
                goBackToPassword();
                return;
            }
            
            document.getElementById('backupUsername').value = username;
            document.getElementById('backupPassword').value = password;
            
            document.getElementById('totpStep').style.display = 'none';
            document.getElementById('backupStep').style.display = 'block';
            document.getElementById('backupCode').focus();
        }
        
        function cancelBackupLogin() {
            document.getElementById('backupStep').style.display = 'none';
            document.getElementById('totpStep').style.display = 'block';
            document.getElementById('totpCode').focus();
        }
        
        async function verifyBackupCode() {
            const username = document.getElementById('backupUsername').value;
            const password = document.getElementById('backupPassword').value;
            const backupCode = document.getElementById('backupCode').value.toUpperCase();
            const btn = document.getElementById('verifyBackupBtn');
            
            if (!backupCode || backupCode.length < 6) {
                toast('请输入有效的备份码', 'error');
                return;
            }
            
            btn.disabled = true;
            btn.innerText = '验证中...';
            
            try {
                const response = await fetch('/api/mfa/login-with-backup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username,
                        password,
                        backup_code: backupCode
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('mfa_enabled', 'true');
                    sessionStorage.removeItem('mfa_username');
                    sessionStorage.removeItem('mfa_password');
                    toast('使用备份码登录成功');
                    setTimeout(() => window.location.href = '/', 1000);
                } else {
                    toast(data.error || '备份码无效', 'error');
                    document.getElementById('backupCode').value = '';
                    document.getElementById('backupCode').focus();
                }
            } catch (error) {
                toast('验证失败，请重试', 'error');
            } finally {
                btn.disabled = false;
                btn.innerText = '验证备份码';
            }
        }
        
        document.getElementById('totpCode')?.addEventListener('input', function(e) {
            this.value = this.value.replace(/[^0-9]/g, '');
            if (this.value.length === 6) {
                verifyTOTP();
            }
        });
        
        document.addEventListener('DOMContentLoaded', function() {
            if (localStorage.getItem('token')) {
                window.location.href = '/';
            }
            document.getElementById('username').focus();
        });
    </script>
</body>
</html>
`;

const adminHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico">
    <title>优选配置管理后台</title>
    <style>${globalCss}</style>
</head>
<body>
    <div id="toast-container"></div>
    <div id="loader" style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);color:#89949B">系统加载中...</div>

    <div class="container" id="app" style="display:none">
        <div class="top-bar">
            <div>
                <span style="font-weight:bold; color:#5a666d;">CF 优选配置管理</span> 
                <span style="color:#89949B; font-size:0.9rem;">| Admin</span>
                <span id="mfaBadge" style="margin-left:10px; display:none;" class="mfa-status-badge"></span>
            </div>
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
                <button class="nav-btn" onclick="switchTab('security', this)">安全中心</button>
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
                
                <div class="security-section" id="mfaStatusSection" style="display:none;">
                    <h3>⛑️ 账户安全状态</h3>
                    <div id="mfaStatusDetails">加载中...</div>
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
            
            <div id="security" class="card">
                <div class="mfa-container">
                    <h2>🛡️ 账户安全</h2>
                    
                    <div class="security-section" id="mfaCurrentStatus">
                        <h3>双重验证状态</h3>
                        <div id="mfaStatusContent">加载中...</div>
                        <div id="mfaActions" style="margin-top: 15px;">
                            <button class="nav-btn active" onclick="startMfaSetup()" id="enableMfaBtn">启用双重验证</button>
                            <button class="nav-btn danger" onclick="disableMfaConfirm()" id="disableMfaBtn" style="display:none;">禁用双重验证</button>
                        </div>
                    </div>
                    
                    <div id="mfaSetupSteps" style="display:none;"></div>
                </div>
            </div>

        </div>

        <footer class="footer">
            <p>Powered by <a href="https://www.yangzihome.space" target="_blank">YZFN</a></p>
        </footer>
    </div>

    <!-- 修改密码弹窗 -->
    <div class="modal-overlay" id="pwdModal">
        <div class="modal">
            <h3 style="margin-top:0; color:#3d474d">修改管理员密码</h3>
            <div style="margin-bottom:15px;">
                <input type="password" id="oldP" placeholder="当前旧密码" autocomplete="current-password">
                <input type="password" id="newP" placeholder="新密码" autocomplete="new-password">
                <input type="password" id="confirmP" placeholder="确认新密码" autocomplete="new-password">
            </div>
            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button class="nav-btn" onclick="document.getElementById('pwdModal').style.display='none'">取消</button>
                <button class="nav-btn active" onclick="changePwd()">确认修改</button>
            </div>
        </div>
    </div>

    <!-- 域名编辑弹窗 -->
    <div class="modal-overlay" id="editDomModal">
        <div class="modal">
            <h3 style="margin-top:0; color:#3d474d">编辑域名</h3>
            <input type="hidden" id="editId">
            <div style="margin-bottom:15px;">
                <label style="display:block;margin-bottom:5px;font-size:0.9rem;color:#5a666d;">域名:</label>
                <input type="text" id="editDomain">
                <label style="display:block;margin-bottom:5px;font-size:0.9rem;color:#5a666d;">备注:</label>
                <input type="text" id="editRemark">
            </div>
            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button class="nav-btn" onclick="document.getElementById('editDomModal').style.display='none'">取消</button>
                <button class="nav-btn active" onclick="updateDomain()">保存修改</button>
            </div>
        </div>
    </div>



    <!-- MFA 验证密码弹窗（统一风格，替换原生 prompt） -->
    <div class="modal-overlay" id="mfaAuthModal" onclick="event.target===this && (this.style.display='none')">
        <div class="modal">
            <h3 style="margin-top:0; color:#3d474d">验证身份以启用双重验证</h3>
            <div style="margin-top:10px;">
                <input type="password" id="mfaAuthPassword" placeholder="请输入当前密码" autocomplete="current-password" onkeydown="if(event.key==='Enter') submitMfaAuthModal()">
                <div id="mfaAuthError" style="color:#ef4444; margin-top:8px; display:none;"></div>
            </div>
            <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:20px;">
                <button class="nav-btn" onclick="document.getElementById('mfaAuthModal').style.display='none'; window._mfaAuthCallback=null;">取消</button>
                <button class="nav-btn active" onclick="submitMfaAuthModal()">继续</button>
            </div>
        </div>
    </div>

    <!-- 备份码显示弹窗 -->
    <div class="modal-overlay" id="backupCodesModal" onclick="event.target===this && (this.style.display='none')">
        <div class="modal">
            <div style="max-height: 80vh; overflow-y: auto;">
                <h3 style="margin-top:0; color:#3d474d; position: sticky; top: 0; background: white; padding-bottom: 10px; border-bottom: 1px solid #eee;">🔐 备份码</h3>
                
                <div style="color: #dc2626; background: #fee2e2; padding: 10px; border-radius: 6px; margin: 15px 0; font-size: 0.9rem;">
                    <strong>重要提示：</strong>
                    <p>• 请立即保存这些备份码！</p>
                    <p>• 每个备份码只能使用一次</p>
                    <p>• 保存后无法再次查看完整列表</p>
                </div>
                
                <div id="backupCodesList" class="backup-codes-box" style="font-size: 1rem; line-height: 2.5;"></div>
                
                <div style="margin-top: 20px;">
                    <button class="nav-btn active" onclick="printBackupCodes()" style="margin-right: 10px;">🖨️ 打印</button>
                    <button class="nav-btn" onclick="copyBackupCodes()">📋 复制</button>
                </div>
                
                <div style="margin-top: 20px; font-size: 0.9rem; color: #6b7280;">
                    <p><strong>如何使用备份码：</strong></p>
                    <p>• 登录时选择"使用备份码登录"</p>
                    <p>• 输入完整的8位备份码</p>
                    <p>• 使用后该备份码将立即失效</p>
                </div>
                
                <div style="display:flex; justify-content:flex-end; margin-top: 20px;">
                    <button class="nav-btn active" onclick="document.getElementById('backupCodesModal').style.display='none'">我已保存</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const token = localStorage.getItem('token');
        if (!token) window.location.href = '/login';

        // ============ 工具函数 ============
        function toast(message, type = 'info') { 
            const c = document.getElementById('toast-container'); 
            const d = document.createElement('div'); 
            d.className = 'toast'; 
            d.innerHTML = (type === 'error' ? '❌ ' : '✅ ') + message; 
            c.appendChild(d); 
            setTimeout(() => d.remove(), 5000); 
        }
        
        function fmtDate(timestamp) { 
            if (!timestamp || timestamp === 0) return '从未';
            const date = new Date(timestamp);
            return date.toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
        
        async function api(path, method = 'GET', body) {
            try {
                const res = await fetch('/api/' + path, { 
                    method, 
                    headers: {
                        'Authorization': 'Bearer ' + token, 
                        'Content-Type': 'application/json'
                    }, 
                    body: body ? JSON.stringify(body) : null 
                });
                
                if (res.status === 401) {
                    toast('会话已过期，请重新登录', 'error');
                    setTimeout(() => logout(), 2000);
                    return null;
                }
                
                if (res.status === 403) {
                    const error = await res.json();
                    toast(error.error || '权限不足', 'error');
                    return null;
                }
                
                if (res.status === 404) {
                    toast('API端点不存在', 'error');
                    return null;
                }
                
                if (res.status === 500) {
                    toast('服务器内部错误', 'error');
                    return null;
                }
                
                const data = await res.json();
                if (data.error) {
                    toast(data.error, 'error');
                    return null;
                }
                
                return data;
            } catch(e) { 
                toast('网络错误: ' + e.message, 'error'); 
                return null; 
            }
        }
        
        function logout() { 
            localStorage.clear();
            sessionStorage.clear();
            window.location.href = '/login'; 
        }

        // ============ 状态管理 ============
        let domState = { page: 1, size: 10, total: 0, sort: 'id', order: 'desc' };
        let ipState = { page: 1, size: 20, total: 0, sort: 'created_at', order: 'desc' };
        let uuidState = { page: 1, size: 10, total: 0, sort: 'updated_at', order: 'desc' };
        let autoUpdateSettings = { global_enabled: false, hostmonit: true, vps789: true };
        let mfaStatus = { enabled: false, last_login: 0, backup_codes: 0 };
        let currentMfaSecret = '';

        // ============ 初始化 ============
        document.addEventListener('DOMContentLoaded', async function() {
            if (!token) {
                window.location.href = '/login';
                return;
            }
            
            try {
                await init();
            } catch (error) {
                document.getElementById('loader').innerHTML = \`
                    <div style="text-align:center; color:#ef4444;">
                        <p>初始化失败</p>
                        <button onclick="location.reload()" class="nav-btn">重试</button>
                    </div>
                \`;
            }
        });

        async function init() {
            try {
                await loadStats();
                await loadAutoUpdateSettings();
                await checkMfaStatus();
                
                document.getElementById('loader').style.display = 'none';
                document.getElementById('app').style.display = 'flex';
                
                toast('系统加载完成');
            } catch (error) {
                console.error('初始化错误:', error);
                throw error;
            }
        }
        
        // ============ 标签页切换 ============
        function switchTab(id, btn) {
            if (!btn) {
                const activeBtn = document.querySelector('.nav-grid .nav-btn.active');
                if (activeBtn) {
                    activeBtn.classList.remove('active');
                }
                const newBtn = document.querySelector(\`.nav-btn[onclick*="switchTab('\${id}'"]\`);
                if (newBtn) {
                    newBtn.classList.add('active');
                }
            } else {
                document.querySelectorAll('.nav-grid .nav-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            }
            
            document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            
            if (id === 'dash') loadStats();
            if (id === 'dom') loadDom();
            if (id === 'ips') loadIp();
            if (id === 'uuids') loadUuid();
            if (id === 'security') updateSecurityTab();
        }

        // ============ 加载统计信息 ============
        async function loadStats() {
            const data = await api('stats');
            if (data) {
                document.getElementById('s-dom').innerText = data.domains;
                document.getElementById('s-ip').innerText = data.ips;
                document.getElementById('s-uuid').innerText = data.uuids;
                
                const statusText = data.autoUpdate === 1 ? 
                    '<span style="color:#10b981">已启用</span>' : 
                    '<span style="color:#ef4444">已关闭</span>';
                document.getElementById('autoUpdateStatus').innerHTML = statusText;
                
                if (data.lastExecuted > 0) {
                    document.getElementById('lastExecuted').innerText = fmtDate(data.lastExecuted);
                } else {
                    document.getElementById('lastExecuted').innerText = '从未执行';
                }
            }
        }

        // ============ 自动更新设置 ============
        async function loadAutoUpdateSettings() {
            const settings = await api('settings/auto-update');
            if (settings) {
                autoUpdateSettings = settings;
                
                document.getElementById('sw-global').checked = settings.global_enabled === 1;
                document.getElementById('sw-hm').checked = settings.hostmonit === 1;
                document.getElementById('sw-v7').checked = settings.vps789 === 1;
                
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
                toast('自动更新设置已保存');
                await loadAutoUpdateSettings();
                await loadStats();
            }
        }

        // ============ MFA功能 ============
        async function checkMfaStatus() {
            const data = await api('mfa/status');
            if (data) {
                mfaStatus = {
                    enabled: data.mfa_enabled,
                    last_login: data.last_mfa_login,
                    backup_codes: data.backup_codes_remaining || 0
                };
                
                updateMfaUI();
            }
        }

        function updateMfaUI() {
            const mfaBadge = document.getElementById('mfaBadge');
            const mfaStatusSection = document.getElementById('mfaStatusSection');
            
            if (mfaStatus.enabled) {
                const lastLogin = mfaStatus.last_login ? 
                    '上次验证: ' + fmtDate(mfaStatus.last_login) : '从未验证';
                const backupCount = mfaStatus.backup_codes > 0 ? 
                    \`，剩余\${mfaStatus.backup_codes}个备份码\` : '，无备份码';
                
                mfaBadge.innerHTML = '🛡️ MFA已启用';
                mfaBadge.className = 'mfa-status-badge mfa-active';
                mfaBadge.style.display = 'inline-flex';
                
                mfaStatusSection.style.display = 'block';
                document.getElementById('mfaStatusDetails').innerHTML = \`
                    <div>双重验证: <span style="color:#10b981">已启用</span></div>
                    <div>\${lastLogin}</div>
                    <div>\${backupCount}</div>

                \`;
            } else {
                mfaBadge.innerHTML = '⚠️ MFA未启用';
                mfaBadge.className = 'mfa-status-badge mfa-inactive';
                mfaBadge.style.display = 'inline-flex';
                mfaStatusSection.style.display = 'none';
            }
            
            updateSecurityTab();
        }

        function updateSecurityTab() {
            const mfaStatusContent = document.getElementById('mfaStatusContent');
            const enableMfaBtn = document.getElementById('enableMfaBtn');
            const disableMfaBtn = document.getElementById('disableMfaBtn');
            
            if (mfaStatus.enabled) {
                const lastLogin = mfaStatus.last_login ? 
                    fmtDate(mfaStatus.last_login) : '从未';
                
                mfaStatusContent.innerHTML = \`
                    <div style="color:#10b981; font-weight:bold; margin-bottom:10px;">
                        ✅ 双重验证已启用
                    </div>
                    <div>上次双重验证登录: \${lastLogin}</div>
                    <div>剩余备份码: <span style="font-weight:bold;">\${mfaStatus.backup_codes}</span> 个</div>
                    <div style="margin-top:15px;">
                        <button class="nav-btn small active" onclick="showBackupCodes()" \${mfaStatus.backup_codes === 0 ? 'disabled' : ''}>
                            查看备份码
                        </button>
                        <button class="nav-btn small" onclick="regenerateBackupCodes()">
                            重新生成备份码
                        </button>
                    </div>
                \`;
                
                enableMfaBtn.style.display = 'none';
                disableMfaBtn.style.display = 'inline-block';
            } else {
                mfaStatusContent.innerHTML = \`
                    <div style="color:#ef4444; font-weight:bold; margin-bottom:10px;">
                        ⚠️ 双重验证未启用
                    </div>
                    <p style="font-size:0.9rem; color:#6b7280; margin:10px 0;">
                        双重验证（MFA）可为您的账户提供额外保护。
                        启用后，登录时需要密码和动态验证码。
                    </p>
                \`;
                
                enableMfaBtn.style.display = 'inline-block';
                disableMfaBtn.style.display = 'none';
            }
        }

        async function startMfaSetup() {
            const username = getCurrentUsername();
            // 使用统一风格的密码验证弹窗代替原生 prompt
            openMfaAuthModal(async (password) => {
                if (!password) return;
                try {
                    const response = await fetch('/api/mfa/init', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            username: username,
                            password: password
                        })
                    });
                    const data = await response.json();
                    if (response.ok) {
                        currentMfaSecret = data.secret;
                        showMfaSetupStep1(data);
                    } else {
                        toast(data.error || '初始化失败', 'error');
                    }
                } catch (error) {
                    toast('网络错误，请重试', 'error');
                }
            });
        }

        function showMfaSetupStep1(data) {
            const setupSteps = document.getElementById('mfaSetupSteps');
            setupSteps.style.display = 'block';
            setupSteps.innerHTML = \`
                <div class="security-step">
                    <h4>步骤 1: 输入密钥</h4>
                    <p style="font-size:0.9rem; color:#6b7280;">
                        使用身份验证器App（如Google Authenticator、Microsoft Authenticator、Authy等）：
                    </p>
                    
                    <div class="qr-code-container">
                        <div class="secret-display">
                            \${currentMfaSecret} 
                            <button class="copy-btn" onclick="copyToClipboard('\${currentMfaSecret}')">复制</button>
                        </div>
                        
                        <div class="qr-instructions">
                            <ol>
                                <li>打开身份验证器App</li>
                                <li>点击"添加账户"或"+"按钮</li>
                                <li>选择"手动输入密钥"</li>
                                <li>输入密钥：<strong>\${currentMfaSecret}</strong></li>
                                <li>账户名：<strong>\${getCurrentUsername()}</strong></li>
                                <li>类型：<strong>TOTP</strong></li>
                                <li>位数：<strong>6</strong></li>
                                <li>周期：<strong>30秒</strong></li>
                            </ol>
                        </div>
                    </div>
                    
                    <div style="text-align:center; margin:20px 0;">
                        <button class="nav-btn active" onclick="showMfaSetupStep2()">我已添加账户，继续</button>
                        <button class="nav-btn" onclick="cancelMfaSetup()">取消</button>
                    </div>
                </div>
            \`;
            
            switchTab('security');
        }

        function showMfaSetupStep2() {
            const setupSteps = document.getElementById('mfaSetupSteps');
            setupSteps.innerHTML = \`
                <div class="security-step">
                    <h4>步骤 2: 验证</h4>
                    <p style="font-size:0.9rem; color:#6b7280;">
                        请在输入框中输入身份验证器App生成的6位验证码：
                    </p>
                    
                    <div style="text-align: center; margin: 20px 0;">
                        <div style="display:flex; gap:10px; justify-content:center; margin:20px 0;">
                            <input type="text" id="verifyTOTPInput" maxlength="6" 
                                   pattern="[0-9]{6}" inputmode="numeric" 
                                   style="font-size:1.5rem; text-align:center; letter-spacing:10px; width:150px;"
                                   placeholder="000000">
                        </div>
                        
                        <div style="display:flex; gap:10px; justify-content:center;">
                            <button class="nav-btn" onclick="showMfaSetupStep1()">返回上一步</button>
                            <button class="nav-btn active" onclick="verifyMfaSetup()">验证并完成</button>
                        </div>
                    </div>
                </div>
            \`;
            
            setTimeout(() => {
                document.getElementById('verifyTOTPInput').focus();
            }, 100);
        }

        async function verifyMfaSetup() {
            const totpCode = document.getElementById('verifyTOTPInput').value;
            const username = getCurrentUsername();
            
            if (!totpCode || totpCode.length !== 6) {
                toast('请输入6位验证码', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/mfa/verify-first', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: username,
                        totp_code: totpCode,
                        secret: currentMfaSecret
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showBackupCodes(data.backup_codes);
                    currentMfaSecret = '';
                    // 隐藏并清空设置面板，避免在启用后仍显示步骤内容
                    const setupSteps = document.getElementById('mfaSetupSteps');
                    if (setupSteps) {
                        setupSteps.style.display = 'none';
                        setupSteps.innerHTML = '';
                    }
                    await checkMfaStatus();
                    toast('双重验证已成功启用！');
                } else {
                    toast(data.error || '验证码无效，请重试', 'error');
                    document.getElementById('verifyTOTPInput').value = '';
                    document.getElementById('verifyTOTPInput').focus();
                }
            } catch (error) {
                toast('网络错误，请重试', 'error');
            }
        }

        function cancelMfaSetup() {
            const setupSteps = document.getElementById('mfaSetupSteps');
            setupSteps.style.display = 'none';
            setupSteps.innerHTML = '';
            currentMfaSecret = '';
            updateSecurityTab();
        }

        function showBackupCodes(backupCodes) {
            if (!backupCodes) {
                toast('没有备份码数据', 'error');
                return;
            }
            
            const modal = document.getElementById('backupCodesModal');
            const listContainer = document.getElementById('backupCodesList');
            
            let listHTML = '';
            backupCodes.forEach((code, index) => {
                listHTML += \`<div class="backup-code">\${code}</div>\`;
                if ((index + 1) % 5 === 0) {
                    listHTML += '<br>';
                }
            });
            
            listContainer.innerHTML = listHTML;
            modal.style.display = 'flex';
        }

        function disableMfaConfirm() {
            if (confirm('确定要禁用双重验证吗？禁用后您的账户将只有密码保护。')) {
                openMfaAuthModal(async (password) => {
                    if (!password) return;
                    disableMfa(password);
                });
            }
        }

        async function disableMfa(password) {
            const res = await api('mfa/disable', 'POST', { password });
            if (res && res.success) {
                await checkMfaStatus();
                toast('双重验证已禁用');
            }
        }

        async function regenerateBackupCodes() {
            openMfaAuthModal(async (password) => {
                if (!password) return;
                const res = await api('mfa/backup-codes/regenerate', 'POST', { password });
                if (res && res.success) {
                    showBackupCodes(res.backup_codes);
                    await checkMfaStatus();
                    toast('备份码已重新生成');
                }
            });
        }

        // ============ 通用工具函数 ============
        function getCurrentUsername() {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                return payload.sub || 'admin';
            } catch {
                return 'admin';
            }
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                toast('已复制到剪贴板');
            }).catch(err => {
                toast('复制失败', 'error');
            });
        }

        function printBackupCodes() {
            const printWindow = window.open('', '_blank');
            const codes = Array.from(document.querySelectorAll('.backup-code'))
                .map(el => el.textContent)
                .join('\\n');
            
            printWindow.document.write(\`
                <html>
                <head>
                    <title>MFA备份码 - \${getCurrentUsername()}</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        h1 { color: #333; }
                        .codes { font-family: monospace; font-size: 1.2em; line-height: 2; }
                        .code { display: inline-block; margin: 5px; padding: 5px 10px; border: 1px solid #ccc; }
                        .warning { color: #d00; background: #fee; padding: 10px; border-radius: 5px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <h1>MFA备份码</h1>
                    <p>账户: \${getCurrentUsername()}</p>
                    <p>生成时间: \${new Date().toLocaleString()}</p>
                    
                    <div class="warning">
                        <strong>重要提示：</strong>
                        <p>• 请妥善保存此页</p>
                        <p>• 每个备份码只能使用一次</p>
                        <p>• 用完后请重新生成</p>
                    </div>
                    
                    <div class="codes">
                        \${codes.split('\\n').map(code => \`<div class="code">\${code}</div>\`).join('')}
                    </div>
                </body>
                </html>
            \`);
            printWindow.document.close();
            printWindow.print();
        }

        function copyBackupCodes() {
            const codes = Array.from(document.querySelectorAll('.backup-code'))
                .map(el => el.textContent)
                .join('\\n');
            
            copyToClipboard(codes);
        }

        // ============ Modal控制函数 ============
        function openPwdModal() {
            document.getElementById('pwdModal').style.display = 'flex';
        }

        // 打开一个统一风格的验证密码弹窗，回调在确认后执行
        function openMfaAuthModal(callback) {
            window._mfaAuthCallback = callback;
            const modal = document.getElementById('mfaAuthModal');
            modal.style.display = 'flex';
            document.getElementById('mfaAuthPassword').value = '';
            document.getElementById('mfaAuthError').style.display = 'none';
            setTimeout(()=>document.getElementById('mfaAuthPassword').focus(), 100);
        }

        function submitMfaAuthModal() {
            const pwd = document.getElementById('mfaAuthPassword').value;
            if (!pwd) {
                const err = document.getElementById('mfaAuthError');
                err.textContent = '请输入当前密码';
                err.style.display = '';
                return;
            }
            const cb = window._mfaAuthCallback;
            window._mfaAuthCallback = null;
            document.getElementById('mfaAuthModal').style.display = 'none';
            if (typeof cb === 'function') cb(pwd);
        }

        function openMfaSettingsModal() { return; /* removed */
            document.getElementById('mfaModal').style.display = 'flex';
            document.getElementById('mfaModalContent').innerHTML = \`
                <p>请选择您要进行的操作：</p>
                <div style="margin-top: 20px;">
                    <button class="nav-btn" style="width:100%; margin-bottom:10px;" onclick="startMfaSetup()">启用双重验证</button>
                    <button class="nav-btn danger" style="width:100%;" onclick="disableMfaConfirm()">禁用双重验证</button>
                </div>
            \`;
        }

        async function changePwd() {
            const oldP = document.getElementById('oldP').value;
            const newP = document.getElementById('newP').value;
            const confirmP = document.getElementById('confirmP').value;
            
            if (!oldP || !newP || !confirmP) {
                toast('请填写所有密码字段', 'error');
                return;
            }
            
            if (newP !== confirmP) {
                toast('新密码和确认密码不一致', 'error');
                return;
            }
            
            if (newP.length < 6) {
                toast('新密码至少需要6位', 'error');
                return;
            }
            
            const res = await api('change-password', 'POST', {
                oldPassword: oldP,
                newPassword: newP
            });
            
            if (res && res.success) {
                toast('密码修改成功');
                document.getElementById('pwdModal').style.display = 'none';
                document.getElementById('oldP').value = '';
                document.getElementById('newP').value = '';
                document.getElementById('confirmP').value = '';
            }
        }

        // ============ 域名管理 ============
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
            if(!d) return toast('域名不能为空', 'error');
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
            if(!domain) return toast('域名不能为空', 'error');
            if(await api('domains', 'PUT', { id, domain, remark })) { 
                toast('修改成功'); 
                document.getElementById('editDomModal').style.display = 'none'; 
                loadDom(); 
            }
        }
        
        function changeDomPage(d) { changePage('dom', d, domState, loadDom); }
        function changeDomSize() { changeSize('dom', domState, loadDom); }
        function sortDom(f) { changeSort(f, domState, loadDom); }

        // ============ IP管理 ============
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
                toast(\`更新失败: \${res.message}\`, 'error'); 
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

        // ============ UUID管理 ============
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

        // ============ 通用分页和排序函数 ============
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

        // ============ 关闭Modal函数 ============
        function closeAllModals() {
            document.querySelectorAll('.modal-overlay').forEach(modal => {
                modal.style.display = 'none';
            });
        }

        // 点击Modal外部关闭
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === this) {
                    this.style.display = 'none';
                }
            });
        });

        // ============ 键盘快捷键 ============
        document.addEventListener('keydown', function(e) {
            // ESC键关闭所有Modal
            if (e.key === 'Escape') {
                closeAllModals();
            }
            
            // Ctrl+S保存自动更新设置
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                saveAutoUpdateSettings();
            }
        });
    </script>
</body>
</html>
`;

// =================================================================
//  8. 主入口
// =================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        
        // 处理API请求
        if (url.pathname.startsWith('/api')) {
            return await handleApi(request, env);
        }
        
        // 处理静态页面
        if (url.pathname === '/login') {
            return new Response(loginHtml, { 
                headers: { 
                    'Content-Type': 'text/html;charset=UTF-8',
                    'Cache-Control': 'no-cache, no-store, must-revalidate'
                } 
            });
        }
        
        // 默认返回管理页面
        const adminToken = request.headers.get('Cookie')?.match(/admin_token=([^;]+)/)?.[1];
        if (!adminToken && !url.pathname.endsWith('.ico') && !url.pathname.endsWith('.css')) {
            // 如果用户可能已经登录，检查localStorage token
            // 这里我们直接返回页面，让前端JavaScript处理重定向
        }
        
        return new Response(adminHtml, { 
            headers: { 
                'Content-Type': 'text/html;charset=UTF-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            } 
        });
    },
    
    async scheduled(event, env, ctx) {
        ctx.waitUntil((async () => {
            console.log('定时IP更新任务开始执行');
            try {
                await runIpUpdateTask(env);
                console.log('定时IP更新任务完成');
            } catch (error) {
                console.error('定时IP更新任务失败:', error);
            }
        })());
    }
};
