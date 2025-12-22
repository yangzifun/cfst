/* =================================================================
 *  Cloudflare Worker: Config Manager + External Link
 *  功能：配置存储、编辑、订阅管理，包含跳转至配置生成的按钮
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
        headers: { 'Content-Type': 'application/json;charset=UTF-8' },
    });
}

function getProtocol(configStr) {
    if (!configStr || typeof configStr !== 'string') return 'unknown';
    if (configStr.startsWith('vmess://')) return 'vmess';
    if (configStr.startsWith('vless://')) return 'vless';
    if (configStr.startsWith('trojan://')) return 'trojan';
    return 'unknown';
}

function extractRemarkFromConfig(configStr, protocol) {
    try {
        if (protocol === 'vmess') {
            const vmessObj = JSON.parse(b64_to_utf8(configStr.substring(8)));
            return vmessObj.ps || vmessObj.remark || null;
        }
        if (protocol === 'vless' || protocol === 'trojan') {
            const url = new URL(configStr);
            if (url.hash) return decodeURIComponent(url.hash.substring(1));
        }
    } catch (e) { }
    return null;
}

// =================================================================
//  DATABASE LOGIC (数据库操作)
// =================================================================

// 获取配置列表
async function fetchConfigsByUuidFromDB(uuid, env) {
    const db = env.DB;
    if (!db) return [];
    try {
        const stmt = db.prepare('SELECT id, config_data, protocol, remark FROM configs WHERE uuid = ? ORDER BY id ASC');
        const { results } = await stmt.bind(uuid).all();
        return results;
    } catch (e) { return []; }
}

// 订阅输出 (Raw Base64)
async function handleRawSubscription(uuid, env) {
    if (!uuid) return jsonResponse({ error: 'UUID Required' }, 400);
    const configs = await fetchConfigsByUuidFromDB(uuid, env);
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
//  API HANDLERS (接口逻辑)
// =================================================================

async function handleAddConfig(request, env) {
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效 JSON' }, 400); }
    const { uuid, config_data } = body;
    if (!uuid || !config_data) return jsonResponse({ error: '字段缺失' }, 400);
    
    const lines = config_data.split('\n').map(l => l.trim()).filter(Boolean);
    const stmts = [];
    for (const line of lines) {
        const p = getProtocol(line);
        if (p === 'unknown') continue;
        const remark = extractRemarkFromConfig(line, p);
        stmts.push(env.DB.prepare('INSERT INTO configs (uuid, config_data, protocol, remark, created_at, updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(uuid,config_data) DO NOTHING').bind(uuid, line, p, remark, Date.now(), Date.now()));
    }
    if (stmts.length === 0) return jsonResponse({ error: '无有效配置' }, 400);
    await env.DB.batch(stmts);
    return jsonResponse({ success: true });
}

async function handleUpdateConfig(request, env) {
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效JSON' }, 400); }
    const { id, config_data } = body;
    
    const protocol = getProtocol(config_data);
    if(protocol === 'unknown') return jsonResponse({ error: '不支持的配置格式' }, 400);
    const remark = extractRemarkFromConfig(config_data, protocol);
    
    try {
        const res = await env.DB.prepare('UPDATE configs SET config_data = ?, protocol = ?, remark = ?, updated_at = ? WHERE id = ?')
            .bind(config_data, protocol, remark, Date.now(), id).run();
        return res.changes > 0 ? jsonResponse({ success: true, message: 'Updated' }) : jsonResponse({ error: '未变更' }, 404);
    } catch(e) { return jsonResponse({ error: e.message }, 500); }
}

async function handleGetConfigs(uuid, env) {
    const results = await fetchConfigsByUuidFromDB(uuid, env);
    return jsonResponse({ uuid, configs: results });
}

async function handleDelete(type, value, env) {
    const sql = type === 'uuid' ? 'DELETE FROM configs WHERE uuid = ?' : 'DELETE FROM configs WHERE id = ?';
    await env.DB.prepare(sql).bind(value).run();
    return jsonResponse({ success: true });
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

        const manageUUID = new URLPattern({ pathname: '/manage/configs/:uuid' });
        const manageID = new URLPattern({ pathname: '/manage/configs/id/:id' });
        const subUUID = new URLPattern({ pathname: '/sub/:uuid' });

        try {
            if (method === 'GET') {
                if (path === '/') return new Response(managePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                
                const subMatch = subUUID.exec(url);
                if (subMatch) return await handleRawSubscription(subMatch.pathname.groups.uuid, env);

                const uuidMatch = manageUUID.exec(url);
                if (uuidMatch) return await handleGetConfigs(uuidMatch.pathname.groups.uuid, env);
            }

            if (method === 'POST' && path === '/manage/configs') return await handleAddConfig(request, env);
            if (method === 'PUT' && path === '/manage/configs') return await handleUpdateConfig(request, env);
            
            if (method === 'DELETE') {
                const idMatch = manageID.exec(url);
                if (idMatch) return await handleDelete('id', idMatch.pathname.groups.id, env);
                const uuidMatch = manageUUID.exec(url);
                if (uuidMatch) return await handleDelete('uuid', uuidMatch.pathname.groups.uuid, env);
            }

            return new Response('404 Not Found', { status: 404 });
        } catch (err) {
            return new Response("Error: " + err.message, { status: 500 });
        }
    }
};

// =================================================================
//  FRONTEND CONTENT (Updated with Link)
// =================================================================

const newGlobalStyle = `
html { font-size: 87.5%; } body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 40px 20px; box-sizing: border-box; }
.content-group { width: 100%; max-width: 800px; text-align: center; z-index: 10; box-sizing: border-box; }
.profile-name { font-size: 2.2rem; color: #3d474d; margin-bottom: 10px; font-weight: bold;}
.profile-quote { color: #89949B; margin-bottom: 27px; min-height: 1.2em; }
.nav-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-bottom: 27px; }
/* Modified nav-btn for unified A-tag behavior */
.nav-btn { display: inline-flex; align-items: center; justify-content: center; padding: 8px 16px; text-align: center; background: #E8EBED; border: 2px solid #89949B; border-radius: 4px; color: #5a666d; text-decoration: none !important; font-weight: 500; font-size: 0.95rem; line-height: 1.2; transition: all 0.3s; white-space: nowrap; cursor: pointer; box-sizing: border-box; }
.nav-btn:hover:not(:disabled) { background: #89949B; color: white; }
.nav-btn:disabled { opacity: 0.6; cursor: not-allowed;}
.nav-btn.primary { background-color: #5a666d; color: white; border-color: #5a666d;}
.nav-btn.primary:hover:not(:disabled) { background-color: #3d474d; }
.card { background: #f8f9fa; border: 1px solid #E8EBED; border-radius: 8px; padding: 24px; margin-bottom: 24px; text-align: left; }
.card h2 { font-size: 1.5rem; color: #3d474d; margin-top: 0; margin-bottom: 20px; text-align: center;}
.form-group { margin-bottom: 16px; }
.form-group label { display: block; color: #5a666d; font-weight: 500; margin-bottom: 8px; font-size: 0.9rem;}
textarea, input[type="text"], input[type="number"], select { width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px; background: #fff; font-family: 'SF Mono', 'Courier New', monospace; font-size: 0.9rem; box-sizing: border-box; resize: vertical; margin-bottom: 5px;}
textarea:focus, input:focus, select:focus { outline: none; border-color: #3d474d; }
.info-box { background-color: #e8ebed; color: #5a666d; border-left: 4px solid #89949B; padding: 12px 16px; border-radius: 4px; font-size: 0.85rem; text-align: left; line-height: 1.5; margin: 16px 0; }
.footer { margin-top: 40px; text-align: center; color: #89949B; font-size: 0.8rem; }
.footer a { color: #5a666d; text-decoration: none; }
.hidden { display: none; }
#toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast { display: flex; align-items: center; padding: 12px 18px; border-radius: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); font-weight: 500; font-size: 0.9rem; border: 2px solid #89949B; background: #fff; color: #3d474d; opacity: 0; transform: translateX(100%); animation: slideIn 0.5s forwards, fadeOut 0.5s 4.5s forwards; }
@keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
@keyframes fadeOut { from { opacity: 1; } to { opacity: 0; transform: translateX(100%); } }

/* Table & Modal Specific */
.table-container { overflow-x: auto; border: 2px solid #89949B; border-radius: 4px; background: #fff; margin-top:20px;}
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 2px solid #E8EBED; white-space: nowrap; }
th { font-weight: bold; color: #3d474d; background-color: #f0f2f5; }
.config-data-cell { white-space: normal; word-break: break-all; max-width: 200px; font-size: 0.8rem; color: #666; }
.actions-cell button { margin-right: 5px; padding: 4px 8px; font-size: 0.8rem; }

/* Modal Styles */
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100; display: flex; align-items: center; justify-content: center; opacity: 0; pointer-events: none; transition: opacity 0.3s; }
.modal-overlay.open { opacity: 1; pointer-events: auto; }
.modal { background: #fff; width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; border-radius: 8px; padding: 25px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); transform: translateY(-20px); transition: transform 0.3s; }
.modal-overlay.open .modal { transform: translateY(0); }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; border-bottom: 2px solid #E8EBED; padding-bottom: 10px; }
.modal-title { font-size: 1.25rem; font-weight: bold; color: #3d474d; }
.modal-close { cursor: pointer; font-size: 1.5rem; color: #89949B; line-height: 1; }
.modal-body { text-align: left; }
.edit-field { margin-bottom: 12px; }
.edit-field label { font-size: 0.85rem; color: #89949B; margin-bottom: 4px; display: block; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
`;

const managePageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
  <title>YZFN 配置管理</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>
  
  <!-- Editor Modal -->
  <div id="editModalOverlay" class="modal-overlay">
    <div class="modal">
      <div class="modal-header">
        <span class="modal-title">编辑配置 (Editor)</span>
        <span class="modal-close" onclick="closeEditModal()">&times;</span>
      </div>
      <div class="modal-body">
        <input type="hidden" id="edit-id"><input type="hidden" id="edit-protocol">
        <div class="grid-2">
            <div class="edit-field"><label>别名 (Remarks)</label><input type="text" id="edit-ps"></div>
            <div class="edit-field"><label>端口 (Port)</label><input type="number" id="edit-port"></div>
        </div>
        <div class="edit-field"><label>地址 (Address)</label><input type="text" id="edit-add"></div>
        <div class="edit-field"><label>UUID / Password</label><input type="text" id="edit-id-uuid"></div>
        <div class="grid-2">
            <div class="edit-field"><label>传输 (Net)</label><select id="edit-net"><option value="tcp">TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option></select></div>
            <div class="edit-field"><label>伪装 (Type)</label><input type="text" id="edit-type" placeholder="none"></div>
        </div>
        <div class="grid-2">
            <div class="edit-field"><label>伪装域名 (Host)</label><input type="text" id="edit-host"></div>
            <div class="edit-field"><label>路径 (Path)</label><input type="text" id="edit-path"></div>
        </div>
        <div class="grid-2">
             <div class="edit-field"><label>TLS</label><select id="edit-tls"><option value="">关闭</option><option value="tls">开启 TLS</option></select></div>
             <div class="edit-field"><label>SNI</label><input type="text" id="edit-sni"></div>
        </div>
        <div style="margin-top: 20px; text-align: right;">
            <button class="nav-btn" onclick="closeEditModal()">取消</button>
            <button class="nav-btn primary" onclick="saveEditedConfig()">保存修改</button>
        </div>
      </div>
    </div>
  </div>

  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">配置管理器</h1>
      <p class="profile-quote">节点存储与订阅管理</p>
      
      <!-- Action Buttons (Modified for Unified Style) -->
      <div class="nav-grid">
         <button class="nav-btn primary" disabled style="opacity:1;cursor:default;">管理面板</button>
         <!-- Added 'primary' class to make the link look exactly like the main button -->
         <a href="https://cfst.api.yangzifun.org" target="_blank" class="nav-btn primary">配置生成</a>
      </div>

      <div class="card">
        <h2>1. 检索订阅</h2>
        <div class="form-group" style="display:flex; gap:10px;">
           <input type="text" id="queryUuidInput" placeholder="请输入您的 UUID" style="margin-bottom:0;">
           <button id="queryBtn" class="nav-btn primary" onclick="manageQueryByUuid()">查询</button>
        </div>
        
        <!-- Modified Subscription Link Area: Now uses input field for unified style -->
        <div id="subLinkDisplay" class="form-group hidden" style="display:none; gap:10px; margin-top:10px;">
           <input type="text" id="subUrlLink" readonly style="margin-bottom:0; color:#5a666d; background-color: #f8f9fa;">
           <button class="nav-btn" onclick="copySubLink()" style="white-space: nowrap;">复制</button>
        </div>
      </div>

      <div id="resultCard" class="card hidden">
        <h2>2. 配置列表</h2>
        <div style="text-align:right; margin-bottom:10px;">
           <button class="nav-btn" style="background:#d44; color:#fff; border-color:#d44;" onclick="deleteAll()">删除本组所有</button>
        </div>
        <div id="queryResultsContainer"></div>
      </div>

      <div id="addCard" class="card hidden">
        <h2>3. 添加新节点</h2>
        <div class="form-group"><textarea id="addConfigData" placeholder="支持批量添加：
vmess://...
vless://...
trojan://..." rows="4"></textarea></div>
        <button onclick="manageAddConfig()" class="nav-btn primary" style="width:100%">添加到当前 UUID</button>
      </div>

      <footer class="footer"><p>Powered by <a href="https://www.yangzihome.space">YZFN</a> | <a href="https://www.yangzihome.space/security.html">安全声明</a></p></footer>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = { success: '✅', error: '❌', info: 'ℹ️' };
    function showToast(m,t='info'){const c=document.getElementById('toast-container');const x=document.createElement('div');x.className='toast';x.innerHTML=\`<span>\${toastIcons[t]} \${m}</span>\`;c.appendChild(x);setTimeout(()=>x.remove(),4000)}
    function setButtonLoading(b,l,t){if(l){b.ds=b.innerHTML;b.disabled=true;b.innerHTML='...'}else{b.disabled=false;if(b.ds)b.innerHTML=b.ds}}

    /* Parser */
    function b64DecodeUnicode(str) { return decodeURIComponent(atob(str).split('').map(c=>'%'+('00'+c.charCodeAt(0).toString(16)).slice(-2)).join('')); }
    function b64EncodeUnicode(str) { return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,(m,p1)=>String.fromCharCode(parseInt(p1,16)))); }

    /* Modal Logic */
    function openEditModal(config) {
        document.getElementById('edit-id').value = config.id;
        let p = 'unknown'; const l = config.config_data;
        if(l.startsWith('vmess://')) p='vmess'; else if(l.startsWith('vless://')) p='vless'; else if(l.startsWith('trojan://')) p='trojan';
        document.getElementById('edit-protocol').value = p;
        ['ps','add','port','id-uuid','net','type','host','path','tls','sni'].forEach(k=>document.getElementById('edit-'+k).value='');
        try {
            if (p === 'vmess') {
                const c = JSON.parse(b64DecodeUnicode(l.substring(8)));
                document.getElementById('edit-ps').value = c.ps||''; document.getElementById('edit-add').value = c.add||''; document.getElementById('edit-port').value = c.port||''; document.getElementById('edit-id-uuid').value = c.id||''; document.getElementById('edit-net').value = c.net||'tcp'; document.getElementById('edit-type').value = c.type||''; document.getElementById('edit-host').value = c.host||''; document.getElementById('edit-path').value = c.path||''; document.getElementById('edit-tls').value = c.tls||''; document.getElementById('edit-sni').value = c.sni||'';
            } else if (p === 'vless' || p === 'trojan') {
                const u = new URL(l);
                document.getElementById('edit-ps').value = u.hash?decodeURIComponent(u.hash.substring(1)):''; document.getElementById('edit-add').value = u.hostname; document.getElementById('edit-port').value = u.port; document.getElementById('edit-id-uuid').value = u.username; document.getElementById('edit-net').value = u.searchParams.get('type')||'tcp'; document.getElementById('edit-type').value = u.searchParams.get('headerType')||''; document.getElementById('edit-host').value = u.searchParams.get('host')||''; document.getElementById('edit-path').value = u.searchParams.get('path')||u.searchParams.get('serviceName')||''; document.getElementById('edit-tls').value = u.searchParams.get('security')==='tls'?'tls':''; document.getElementById('edit-sni').value = u.searchParams.get('sni')||'';
            }
        } catch(e) { alert('解析失败'); return; }
        document.getElementById('editModalOverlay').classList.add('open');
    }
    function closeEditModal() { document.getElementById('editModalOverlay').classList.remove('open'); }
    
    async function saveEditedConfig() {
        const id=document.getElementById('edit-id').value; const proto=document.getElementById('edit-protocol').value;
        const ps=document.getElementById('edit-ps').value; const add=document.getElementById('edit-add').value; const port=document.getElementById('edit-port').value; const uuid=document.getElementById('edit-id-uuid').value; const net=document.getElementById('edit-net').value; const type=document.getElementById('edit-type').value; const host=document.getElementById('edit-host').value; const path=document.getElementById('edit-path').value; const tls=document.getElementById('edit-tls').value; const sni=document.getElementById('edit-sni').value;
        let nL = '';
        if (proto === 'vmess') {
            nL = 'vmess://' + b64EncodeUnicode(JSON.stringify({v:"2",ps,add,port,id:uuid,aid:"0",scy:"auto",net,type,host,path,tls,sni}));
        } else {
            let u = new URL(\`\${proto}://\${uuid}@\${add}:\${port}\`);
            if(net!=='tcp') u.searchParams.set('type',net); if(type) u.searchParams.set('headerType',type); if(tls==='tls') { u.searchParams.set('security','tls'); if(sni) u.searchParams.set('sni',sni); } if(host) u.searchParams.set('host',host); if(path) { if(net==='grpc') u.searchParams.set('serviceName',path); else u.searchParams.set('path',path); }
            u.hash = encodeURIComponent(ps); nL = u.toString();
        }
        const b=document.querySelector('.modal .primary'); const o=b.innerHTML; setButtonLoading(b,true);
        try {
            const r = await fetch('/manage/configs', { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id, config_data: nL}) });
            if((await r.json()).success) { showToast('保存成功','success'); closeEditModal(); manageQueryByUuid(); }
        } catch(e) { showToast(e.message,'error'); } finally { setButtonLoading(b,false,o); }
    }

    /* Main Interaction */
    async function manageQueryByUuid(){
        const b=document.getElementById('queryBtn'); setButtonLoading(b,true);
        const u=document.getElementById('queryUuidInput').value.trim();
        if(!u){ showToast('请输入 UUID','error'); setButtonLoading(b,false,b.innerHTML); return;}
        
        // Show sections
        document.getElementById('resultCard').classList.remove('hidden');
        document.getElementById('addCard').classList.remove('hidden');
        const l=\`\${WORKER_DOMAIN}/sub/\${u}\`; 
        // Modified: Set value to input instead of href/innerText
        const input = document.getElementById('subUrlLink');
        input.value = l; 
        document.getElementById('subLinkDisplay').style.display = 'flex';
        document.getElementById('subLinkDisplay').classList.remove('hidden');

        try{
            const r=await fetch(\`/manage/configs/\${u}\`);
            const c=document.getElementById('queryResultsContainer');
            if(r.status===404){ c.innerHTML='<p style="padding:20px;text-align:center;color:#89949B">未找到配置，请直接添加。</p>'; }
            else {
                const d=await r.json();
                let h='<div class="table-container"><table><thead><tr><th>备注</th><th>协议</th><th>配置</th><th>操作</th></tr></thead><tbody>';
                d.configs.forEach(Row=>{
                    const sc = JSON.stringify(Row).replace(/"/g, '&quot;');
                    h+=\`<tr><td>\${Row.remark||'-'}</td><td>\${Row.protocol}</td><td class="config-data-cell">\${Row.config_data.substring(0,40)}...</td><td class="actions-cell"><button class="nav-btn" data-config="\${sc}" onclick="openEditModal(JSON.parse(this.dataset.config))">编辑</button><button class="nav-btn" style="background:#d44;color:#fff;border-color:#d44" onclick="delOne(\${Row.id})">删除</button></td></tr>\`;
                });
                h+='</tbody></table></div>'; c.innerHTML=h;
            }
        } catch(e){ showToast(e.message,'error'); } finally{ setButtonLoading(b,false,b.innerHTML); }
    }
    
    async function manageAddConfig(){
        const u=document.getElementById('queryUuidInput').value; const d=document.getElementById('addConfigData').value;
        if(!u||!d) return showToast('UUID或配置为空','error');
        await fetch('/manage/configs',{method:'POST', body:JSON.stringify({uuid:u,config_data:d})});
        showToast('添加成功','success'); document.getElementById('addConfigData').value=''; manageQueryByUuid();
    }
    async function delOne(id){ if(confirm('确认删除?')) { await fetch(\`/manage/configs/id/\${id}\`,{method:'DELETE'}); manageQueryByUuid(); } }
    async function deleteAll(){ const u=document.getElementById('queryUuidInput').value; if(confirm('确认清空所有配置?')) { await fetch(\`/manage/configs/\${u}\`,{method:'DELETE'}); manageQueryByUuid(); } }
    function copySubLink(){ navigator.clipboard.writeText(document.getElementById('subUrlLink').value).then(()=>showToast('已复制','success')); }
  </script>
</body>
</html>
`;
