package handler

const indexHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>WebSSH Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@300;400;600;700;800&family=Noto+Sans+SC:wght@300;400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #f0f4ff; --bg2: #e8eeff;
      --surface: #ffffff; --surface2: #f5f7ff;
      --border: #dde3f5;
      --accent: #3b6bff; --accent2: #7c3aed;
      --accent-glow: rgba(59,107,255,0.14);
      --text: #1a2040; --text-muted: #7a88b0;
      --success: #10b981; --error: #ef4444; --warn: #f59e0b;
      --shadow: 0 4px 24px rgba(59,107,255,0.09);
      --shadow-lg: 0 16px 56px rgba(59,107,255,0.14);
      --radius: 14px;
      --font-ui: 'Outfit','Noto Sans SC',sans-serif;
      --font-mono: 'JetBrains Mono',monospace;
    }
    [data-theme="purple-pink"] {
      --bg:#fdf2ff; --surface:#fff; --surface2:#fdf5ff; --border:#ecd5f8;
      --accent:#a855f7; --accent2:#ec4899; --accent-glow:rgba(168,85,247,0.13);
      --text:#2d1040; --text-muted:#9b7ab0;
      --shadow:0 4px 24px rgba(168,85,247,0.09);
      --shadow-lg:0 16px 56px rgba(168,85,247,0.14);
    }
    [data-theme="dark-blue"] {
      --bg:#080e1e; --surface:#111827; --surface2:#1a2236; --border:#1e2d45;
      --accent:#00d4ff; --accent2:#7c3aed; --accent-glow:rgba(0,212,255,0.11);
      --text:#e2e8f0; --text-muted:#64748b;
      --shadow:0 4px 24px rgba(0,0,0,0.35);
      --shadow-lg:0 16px 56px rgba(0,0,0,0.5);
    }
    [data-theme="forest"] {
      --bg:#f0faf4; --surface:#fff; --surface2:#f5fdf8; --border:#c8e6d4;
      --accent:#059669; --accent2:#0891b2; --accent-glow:rgba(5,150,105,0.11);
      --text:#0f2a1e; --text-muted:#6b9e82;
      --shadow:0 4px 24px rgba(5,150,105,0.09);
      --shadow-lg:0 16px 56px rgba(5,150,105,0.14);
    }
    html,body{height:100%;}
    body{background:var(--bg);color:var(--text);font-family:var(--font-ui);min-height:100vh;transition:background .4s,color .4s;}
    .bg-mesh{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden;}
    .bg-mesh::before{content:'';position:absolute;width:120%;height:120%;top:-10%;left:-10%;
      background:radial-gradient(ellipse 60% 50% at 20% 30%,var(--accent-glow),transparent 55%),
                 radial-gradient(ellipse 50% 60% at 80% 70%,rgba(124,58,237,0.07),transparent 55%);
      animation:meshFloat 14s ease-in-out infinite alternate;}
    @keyframes meshFloat{from{transform:translate(0,0) scale(1);}to{transform:translate(20px,-18px) scale(1.06);}}
    .page{position:relative;z-index:1;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px 20px 30px;}
    .topbar{position:fixed;top:0;left:0;right:0;z-index:100;display:flex;align-items:center;justify-content:flex-end;padding:14px 24px;}
    .btn-settings{width:40px;height:40px;border-radius:50%;border:1px solid var(--border);background:var(--surface);color:var(--text-muted);cursor:pointer;
      display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow);transition:all .2s;backdrop-filter:blur(10px);}
    .btn-settings:hover{color:var(--accent);border-color:var(--accent);transform:rotate(60deg);box-shadow:0 0 0 3px var(--accent-glow);}
    .header{text-align:center;margin-bottom:20px;animation:fadeDown .7s cubic-bezier(.22,1,.36,1) both;}
    .header-title-row{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:6px;}
    .header-icon{width:50px;height:50px;border-radius:16px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      display:flex;align-items:center;justify-content:center;flex-shrink:0;
      box-shadow:0 6px 24px var(--accent-glow);animation:iconBob 3.5s ease-in-out infinite;}
    @keyframes iconBob{0%,100%{transform:translateY(0);}50%{transform:translateY(-5px);}}
    .header h1{font-size:clamp(1.6rem,4vw,2.4rem);font-weight:800;letter-spacing:-.03em;
      background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:0;}
    .header .subtitle{font-family:var(--font-mono);font-size:.68rem;color:var(--text-muted);letter-spacing:.22em;text-transform:uppercase;}
    .pill-bar{display:flex;align-items:center;justify-content:center;gap:12px;margin-top:10px;}
    .pill{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:100px;
      background:var(--surface);border:1px solid var(--border);font-size:.7rem;color:var(--text-muted);
      font-family:var(--font-mono);box-shadow:var(--shadow);}
    .pill-dot{width:6px;height:6px;border-radius:50%;background:var(--success);animation:pulse 2s ease-in-out infinite;}
    .card{width:100%;max-width:680px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
      padding:36px 40px;box-shadow:var(--shadow-lg);position:relative;overflow:hidden;
      animation:fadeUp .7s cubic-bezier(.22,1,.36,1) .1s both;backdrop-filter:blur(20px);}
    .card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
      background:linear-gradient(90deg,transparent 0%,var(--accent) 40%,var(--accent2) 70%,transparent 100%);opacity:.75;}
    .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:17px;}
    @media(max-width:600px){.form-grid{grid-template-columns:1fr;}.card{padding:22px 18px;}.header-title-row{gap:10px;}}
    .field{display:flex;flex-direction:column;gap:7px;}
    .field.full{grid-column:1 / -1;}
    label{font-size:.68rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--text-muted);}
    label .req{color:var(--accent);margin-left:2px;}
    .input-wrap{position:relative;display:flex;align-items:center;}
    .input-icon{position:absolute;left:12px;color:var(--text-muted);pointer-events:none;transition:color .2s;}
    input[type=text],input[type=password],input[type=number]{
      width:100%;padding:11px 14px 11px 38px;background:var(--surface2);border:1.5px solid var(--border);
      border-radius:9px;font-family:var(--font-mono);font-size:.87rem;color:var(--text);outline:none;
      transition:border-color .2s,box-shadow .2s,background .2s;}
    input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);background:var(--surface);}
    .input-wrap:focus-within .input-icon{color:var(--accent);}
    input::placeholder{color:var(--text-muted);opacity:.65;}
    .auth-tabs{display:flex;background:var(--surface2);border:1.5px solid var(--border);border-radius:9px;padding:3px;width:fit-content;gap:2px;}
    .auth-tab{padding:7px 18px;border:none;background:transparent;color:var(--text-muted);
      font-family:var(--font-ui);font-size:.8rem;font-weight:600;cursor:pointer;border-radius:7px;transition:all .2s;}
    .auth-tab.active{background:var(--surface);color:var(--accent);box-shadow:0 2px 8px rgba(0,0,0,0.08);}
    .auth-pane{display:none;grid-column:1 / -1;}
    .auth-pane.active{display:contents;}
    .file-wrap{display:flex;align-items:center;background:var(--surface2);border:1.5px solid var(--border);border-radius:9px;overflow:hidden;transition:border-color .2s;}
    .file-wrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
    .file-btn{background:transparent;border:none;border-right:1.5px solid var(--border);padding:10px 15px;
      font-family:var(--font-mono);font-size:.73rem;color:var(--accent);cursor:pointer;display:flex;align-items:center;gap:5px;transition:background .2s;}
    .file-btn:hover{background:var(--accent-glow);}
    .file-name{flex:1;padding:10px 13px;font-family:var(--font-mono);font-size:.76rem;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    #private-key-file{display:none;}
    .btn-connect{grid-column:1 / -1;margin-top:6px;padding:13px 32px;
      background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%);
      border:none;border-radius:9px;color:#fff;font-family:var(--font-ui);font-size:.95rem;font-weight:700;
      letter-spacing:.04em;cursor:pointer;transition:opacity .2s,transform .15s,box-shadow .2s;
      display:flex;align-items:center;justify-content:center;gap:8px;
      box-shadow:0 4px 16px var(--accent-glow);position:relative;overflow:hidden;}
    .btn-connect::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.13),transparent);pointer-events:none;}
    .btn-connect:hover{opacity:.91;transform:translateY(-2px);box-shadow:0 8px 28px var(--accent-glow);}
    .btn-connect:active{transform:translateY(0);}
    .btn-connect:disabled{opacity:.42;cursor:not-allowed;transform:none;}
    /* ---- SETTINGS MODAL ---- */
    .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.28);backdrop-filter:blur(7px);z-index:200;
      display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;transition:opacity .25s;}
    .modal-backdrop.open{opacity:1;pointer-events:all;}
    .modal{width:90%;max-width:460px;background:var(--surface);border:1px solid var(--border);border-radius:18px;
      box-shadow:var(--shadow-lg);overflow:hidden;transform:scale(.95) translateY(10px);
      transition:transform .25s cubic-bezier(.22,1,.36,1);}
    .modal-backdrop.open .modal{transform:scale(1) translateY(0);}
    .modal-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px 16px;border-bottom:1px solid var(--border);}
    .modal-title{font-size:1rem;font-weight:700;color:var(--text);}
    .modal-close{width:30px;height:30px;border-radius:50%;border:1px solid var(--border);background:var(--surface2);
      color:var(--text-muted);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;}
    .modal-close:hover{color:var(--error);border-color:var(--error);background:rgba(239,68,68,.08);}
    .modal-body{padding:20px 24px 26px;display:flex;flex-direction:column;gap:20px;}
    .setting-group{display:flex;flex-direction:column;gap:9px;}
    .setting-label{font-size:.7rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted);}
    .color-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}
    .color-swatch{padding:10px 4px;border-radius:10px;border:2px solid transparent;cursor:pointer;
      display:flex;flex-direction:column;align-items:center;gap:6px;font-size:.67rem;color:var(--text-muted);
      text-align:center;transition:all .2s;background:var(--surface2);font-family:var(--font-ui);}
    .color-swatch:hover{border-color:var(--border);}
    .color-swatch.active{border-color:var(--accent);color:var(--accent);}
    .swatch-dot{width:28px;height:28px;border-radius:50%;}
    .toggle-group{display:flex;background:var(--surface2);border:1.5px solid var(--border);border-radius:9px;padding:3px;gap:2px;width:fit-content;}
    .toggle-btn{padding:6px 20px;border:none;background:transparent;color:var(--text-muted);
      font-family:var(--font-ui);font-size:.82rem;font-weight:600;cursor:pointer;border-radius:7px;transition:all .2s;}
    .toggle-btn.active{background:var(--surface);color:var(--accent);box-shadow:0 2px 8px rgba(0,0,0,0.08);}
    .font-select{width:100%;padding:10px 34px 10px 13px;background:var(--surface2);border:1.5px solid var(--border);
      border-radius:9px;color:var(--text);font-family:var(--font-ui);font-size:.85rem;outline:none;cursor:pointer;
      transition:border-color .2s;appearance:none;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
      background-repeat:no-repeat;background-position:right 12px center;}
    .font-select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
    /* ---- TERMINAL WINDOW ---- */
    #term-window{display:none;position:fixed;inset:0;z-index:300;background:rgba(0,0,0,.42);
      backdrop-filter:blur(9px);align-items:center;justify-content:center;}
    #term-window.open{display:flex;animation:fadeIn .3s ease both;}
    .term-popup{width:calc(100vw - 48px);max-width:960px;height:calc(100vh - 80px);max-height:680px;
      background:#0d1117;border-radius:14px;border:1px solid #1e2d45;overflow:hidden;
      display:flex;flex-direction:column;box-shadow:0 32px 80px rgba(0,0,0,.6);
      animation:popIn .36s cubic-bezier(.22,1,.36,1) both;}
    @keyframes popIn{from{transform:scale(.92) translateY(22px);opacity:0;}to{transform:scale(1) translateY(0);opacity:1;}}
    .term-titlebar{display:flex;align-items:center;padding:10px 16px;background:#111827;border-bottom:1px solid #1e2d45;gap:10px;flex-shrink:0;}
    .term-dots{display:flex;gap:6px;}
    .term-dot{width:12px;height:12px;border-radius:50%;}
    .dot-red{background:#ff5f57;}.dot-yellow{background:#ffbd2e;}.dot-green{background:#28c840;}
    .term-title-text{flex:1;text-align:center;font-family:var(--font-mono);font-size:.72rem;color:#64748b;margin-left:-90px;}
    .btn-disc{display:flex;align-items:center;gap:5px;padding:5px 13px;background:transparent;
      border:1px solid #ef4444;border-radius:6px;color:#ef4444;font-family:var(--font-mono);
      font-size:.7rem;cursor:pointer;transition:all .2s;white-space:nowrap;}
    .btn-disc:hover{background:#ef4444;color:#fff;}
    #terminal{flex:1;overflow:hidden;padding:6px;}
    /* ---- ANIMATIONS ---- */
    @keyframes fadeDown{from{opacity:0;transform:translateY(-18px);}to{opacity:1;transform:translateY(0);}}
    @keyframes fadeUp{from{opacity:0;transform:translateY(18px);}to{opacity:1;transform:translateY(0);}}
    @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
    @keyframes pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.5;transform:scale(.82);}}
    .spinner{width:16px;height:16px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;}
    @keyframes spin{to{transform:rotate(360deg);}}
    .toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(80px);
      background:var(--surface);border:1px solid var(--border);border-radius:100px;
      padding:9px 20px;font-size:.82rem;color:var(--text);box-shadow:var(--shadow-lg);
      z-index:500;transition:transform .35s cubic-bezier(.22,1,.36,1),opacity .3s;
      opacity:0;white-space:nowrap;display:flex;align-items:center;gap:8px;}
    .toast.show{transform:translateX(-50%) translateY(0);opacity:1;}
  </style>
</head>
<body data-theme="blue-white">
<div class="bg-mesh"></div>
<div class="topbar">
  <button class="btn-settings" onclick="openSettings()" title="Settings">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  </button>
</div>
<div class="page">
  <div class="header">
    <div class="header-title-row">
      <div class="header-icon">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
        </svg>
      </div>
      <h1>WebSSH Console</h1>
    </div>
    <p class="subtitle" data-i18n="subtitle">Secure Shell in Your Browser</p>
    <div class="pill-bar">
      <span class="pill"><span class="pill-dot"></span><span data-i18n="pill_ready">就绪</span></span>
      <span class="pill">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <span data-i18n="pill_secure">加密传输</span>
      </span>
    </div>
  </div>
  <div class="card">
    <div class="form-grid">
      <div class="field">
        <label data-i18n="label_host">主机地址 <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          <input type="text" id="host" data-i18n-ph="ph_host" placeholder="192.168.1.1 或 example.com"/>
        </div>
      </div>
      <div class="field">
        <label data-i18n="label_port">端口</label>
        <div class="input-wrap">
          <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
          <input type="number" id="port" value="22" min="1" max="65535"/>
        </div>
      </div>
      <div class="field full">
        <label data-i18n="label_username">用户名</label>
        <div class="input-wrap">
          <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <input type="text" id="username" data-i18n-ph="ph_username" placeholder="root（默认）"/>
        </div>
      </div>
      <div class="field full">
        <div class="auth-tabs">
          <button class="auth-tab active" data-tab="password" data-i18n="tab_password">密码登录</button>
          <button class="auth-tab" data-tab="key" data-i18n="tab_key">私钥登录</button>
        </div>
      </div>
      <div class="auth-pane active" id="pane-password">
        <div class="field full">
          <label data-i18n="label_password">密码</label>
          <div class="input-wrap">
            <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <input type="password" id="password" data-i18n-ph="ph_password" placeholder="请输入密码"/>
          </div>
        </div>
      </div>
      <div class="auth-pane" id="pane-key">
        <div class="field">
          <label data-i18n="label_privatekey">私钥文件</label>
          <div class="file-wrap">
            <button class="file-btn" onclick="document.getElementById('private-key-file').click()">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              <span data-i18n="btn_choose">选择文件</span>
            </button>
            <span class="file-name" id="key-file-name" data-i18n="no_file">未选择私钥文件</span>
          </div>
          <input type="file" id="private-key-file"/>
        </div>
        <div class="field">
          <label data-i18n="label_passphrase">密钥口令</label>
          <div class="input-wrap">
            <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
            <input type="password" id="passphrase" data-i18n-ph="ph_passphrase" placeholder="如需密钥口令请输入"/>
          </div>
        </div>
      </div>
      <button class="btn-connect" id="btn-connect" onclick="connect()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
        <span data-i18n="btn_connect">连接</span>
      </button>
    </div>
  </div>
</div>

<!-- Terminal popup -->
<div id="term-window">
  <div class="term-popup">
    <div class="term-titlebar">
      <div class="term-dots"><div class="term-dot dot-red"></div><div class="term-dot dot-yellow"></div><div class="term-dot dot-green"></div></div>
      <div class="term-title-text" id="term-title">terminal</div>
      <button class="btn-disc" onclick="disconnect()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        <span data-i18n="btn_disconnect">断开连接</span>
      </button>
    </div>
    <div id="terminal"></div>
  </div>
</div>

<!-- Settings Modal -->
<div class="modal-backdrop" id="settings-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title" data-i18n="settings_title">设置</span>
      <button class="modal-close" onclick="closeSettings()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="modal-body">
      <div class="setting-group">
        <div class="setting-label" data-i18n="setting_theme">主题色</div>
        <div class="color-grid">
          <div class="color-swatch active" data-theme="blue-white" onclick="setTheme('blue-white',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#3b6bff,#7c3aed)"></div>
            <span data-i18n="theme_blue">蓝白</span>
          </div>
          <div class="color-swatch" data-theme="purple-pink" onclick="setTheme('purple-pink',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#a855f7,#ec4899)"></div>
            <span data-i18n="theme_purple">紫粉</span>
          </div>
          <div class="color-swatch" data-theme="dark-blue" onclick="setTheme('dark-blue',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#00d4ff,#7c3aed)"></div>
            <span data-i18n="theme_dark">黑蓝</span>
          </div>
          <div class="color-swatch" data-theme="forest" onclick="setTheme('forest',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#059669,#0891b2)"></div>
            <span data-i18n="theme_forest">森绿</span>
          </div>
        </div>
      </div>
      <div class="setting-group">
        <div class="setting-label" data-i18n="setting_lang">语言</div>
        <div class="toggle-group">
          <button class="toggle-btn active" onclick="setLang('zh',this)">中文</button>
          <button class="toggle-btn" onclick="setLang('en',this)">English</button>
        </div>
      </div>
      <div class="setting-group">
        <div class="setting-label" data-i18n="setting_uifont">界面字体</div>
        <select class="font-select" id="ui-font-select" onchange="setUIFont(this.value)">
          <option value="'Outfit','Noto Sans SC',sans-serif">Outfit（默认）</option>
          <option value="'Noto Sans SC',sans-serif">Noto Sans SC</option>
          <option value="system-ui,sans-serif">系统字体</option>
          <option value="Georgia,serif">Georgia（衬线）</option>
        </select>
      </div>
      <div class="setting-group">
        <div class="setting-label" data-i18n="setting_termfont">终端字体</div>
        <select class="font-select" id="term-font-select" onchange="setTermFont(this.value)">
          <option value="'JetBrains Mono',monospace">JetBrains Mono（默认）</option>
          <option value="'Fira Code',monospace">Fira Code</option>
          <option value="'Courier New',monospace">Courier New</option>
          <option value="monospace">系统等宽字体</option>
        </select>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
const i18n={
  zh:{subtitle:'Secure Shell in Your Browser',pill_ready:'就绪',pill_secure:'加密传输',
    label_host:'主机地址',label_port:'端口',label_username:'用户名',
    tab_password:'密码登录',tab_key:'私钥登录',label_password:'密码',
    label_privatekey:'私钥文件',no_file:'未选择私钥文件',btn_choose:'选择文件',
    label_passphrase:'密钥口令',btn_connect:'连接',btn_disconnect:'断开连接',
    settings_title:'设置',setting_theme:'主题色',setting_lang:'语言',
    setting_uifont:'界面字体',setting_termfont:'终端字体',
    theme_blue:'蓝白',theme_purple:'紫粉',theme_dark:'黑蓝',theme_forest:'森绿',
    ph_host:'192.168.1.1 或 example.com',ph_username:'root（默认）',
    ph_password:'请输入密码',ph_passphrase:'如需密钥口令请输入',
    err_host:'请填写主机地址',err_auth:'请提供密码或私钥',
    connecting:'正在连接',connected:'已连接',disconnected:'已断开连接',conn_error:'连接失败'},
  en:{subtitle:'Secure Shell in Your Browser',pill_ready:'Ready',pill_secure:'Encrypted',
    label_host:'Hostname',label_port:'Port',label_username:'Username',
    tab_password:'Password',tab_key:'Private Key',label_password:'Password',
    label_privatekey:'Private Key File',no_file:'No file selected',btn_choose:'Choose File',
    label_passphrase:'Passphrase',btn_connect:'Connect',btn_disconnect:'Disconnect',
    settings_title:'Settings',setting_theme:'Theme',setting_lang:'Language',
    setting_uifont:'UI Font',setting_termfont:'Terminal Font',
    theme_blue:'Blue',theme_purple:'Purple',theme_dark:'Dark',theme_forest:'Forest',
    ph_host:'192.168.1.1 or example.com',ph_username:'root (default)',
    ph_password:'Enter password',ph_passphrase:'Passphrase if needed',
    err_host:'Please enter a hostname',err_auth:'Please provide a password or private key',
    connecting:'Connecting to',connected:'Connected to',disconnected:'Disconnected',conn_error:'Connection failed'}
};
let currentLang='zh',currentTermFont="'JetBrains Mono',monospace";
function t(k){return(i18n[currentLang]||i18n.zh)[k]||k;}
function applyLang(){
  document.querySelectorAll('[data-i18n]').forEach(el=>{
    const k=el.dataset.i18n;
    if(el.tagName==='INPUT')el.placeholder=t(k);else el.textContent=t(k);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>{el.placeholder=t(el.dataset.i18nPh);});
}
function setLang(lang,btn){
  currentLang=lang;
  document.querySelectorAll('.toggle-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  applyLang();
}
function setTheme(theme,el){
  document.body.setAttribute('data-theme',theme);
  document.querySelectorAll('.color-swatch').forEach(s=>s.classList.remove('active'));
  if(el)el.classList.add('active');
  localStorage.setItem('wssh-theme',theme);
}
function setUIFont(font){document.documentElement.style.setProperty('--font-ui',font);localStorage.setItem('wssh-uifont',font);}
function setTermFont(font){currentTermFont=font;localStorage.setItem('wssh-termfont',font);if(term)term.options.fontFamily=font;}
function openSettings(){document.getElementById('settings-modal').classList.add('open');}
function closeSettings(){document.getElementById('settings-modal').classList.remove('open');}
document.getElementById('settings-modal').addEventListener('click',e=>{if(e.target===e.currentTarget)closeSettings();});

let currentTab='password',privateKeyData='';
document.querySelectorAll('.auth-tab').forEach(btn=>{
  btn.addEventListener('click',()=>{
    currentTab=btn.dataset.tab;
    document.querySelectorAll('.auth-tab').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.auth-pane').forEach(p=>p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('pane-'+currentTab).classList.add('active');
  });
});
document.getElementById('private-key-file').addEventListener('change',e=>{
  const file=e.target.files[0];if(!file)return;
  document.getElementById('key-file-name').textContent=file.name;
  const reader=new FileReader();
  reader.onload=ev=>{privateKeyData=ev.target.result;};
  reader.readAsText(file);
});

let ws=null,term=null,fitAddon=null;
function showToast(msg,icon){
  const el=document.getElementById('toast');
  el.textContent=(icon||'')+(icon?' ':'')+msg;
  el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'),3000);
}
function resetBtn(){
  const btn=document.getElementById('btn-connect');
  btn.disabled=false;
  btn.innerHTML='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg><span>'+t('btn_connect')+'</span>';
}
function initTerm(){
  if(term)term.dispose();
  const termEl=document.getElementById('terminal');
  termEl.innerHTML='';
  term=new Terminal({
    theme:{background:'#0d1117',foreground:'#e2e8f0',cursor:'#00d4ff',selectionBackground:'rgba(0,212,255,0.18)',
      black:'#1a2236',red:'#ef4444',green:'#10b981',yellow:'#f59e0b',blue:'#3b82f6',
      magenta:'#a855f7',cyan:'#00d4ff',white:'#e2e8f0',brightBlack:'#334155',
      brightRed:'#f87171',brightGreen:'#34d399',brightYellow:'#fbbf24',brightBlue:'#60a5fa',
      brightMagenta:'#c084fc',brightCyan:'#67e8f9',brightWhite:'#f8fafc'},
    fontFamily:currentTermFont,fontSize:14,lineHeight:1.5,
    cursorBlink:true,cursorStyle:'bar',scrollback:5000,allowTransparency:true,
  });
  fitAddon=new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(termEl);
  setTimeout(()=>fitAddon.fit(),80);
  term.onData(data=>{if(ws&&ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'input',data}));});
}
window.addEventListener('resize',()=>{
  if(fitAddon)fitAddon.fit();
  if(term&&ws&&ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'resize',rows:term.rows,cols:term.cols}));
});
function openTermWindow(label){
  document.getElementById('term-title').textContent=label;
  document.getElementById('term-window').classList.add('open');
  setTimeout(()=>{fitAddon&&fitAddon.fit();term&&term.focus();
    if(ws&&ws.readyState===WebSocket.OPEN&&term)ws.send(JSON.stringify({type:'resize',rows:term.rows,cols:term.cols}));
  },120);
}
function closeTermWindow(){document.getElementById('term-window').classList.remove('open');}
function connect(){
  const host=document.getElementById('host').value.trim();
  const port=parseInt(document.getElementById('port').value)||22;
  const username=document.getElementById('username').value.trim()||'root';
  if(!host){showToast(t('err_host'),'⚠');return;}
  const password=currentTab==='password'?document.getElementById('password').value:'';
  const private_key=currentTab==='key'?privateKeyData:'';
  const passphrase=currentTab==='key'?document.getElementById('passphrase').value:'';
  if(!password&&!private_key){showToast(t('err_auth'),'⚠');return;}
  const btn=document.getElementById('btn-connect');
  btn.disabled=true;
  btn.innerHTML='<div class="spinner"></div><span>'+t('connecting')+' '+host+'</span>';
  const proto=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(proto+'://'+location.host+'/ws');
  ws.onopen=()=>ws.send(JSON.stringify({type:'connect',host,port,username,password,private_key,passphrase}));
  ws.onmessage=e=>{
    const msg=JSON.parse(e.data);
    if(msg.type==='connected'){
      resetBtn();
      const label=username+'@'+host+':'+port;
      showToast(t('connected')+': '+label,'✓');
      initTerm();
      openTermWindow(label);
    }else if(msg.type==='output'){if(term)term.write(msg.data);}
    else if(msg.type==='error'){showToast(t('conn_error')+': '+msg.data,'✗');resetBtn();if(ws){ws.close();ws=null;}closeTermWindow();}
    else if(msg.type==='closed'){showToast(t('disconnected'),'⊗');resetBtn();ws=null;closeTermWindow();}
  };
  ws.onerror=()=>{showToast(t('conn_error'),'✗');resetBtn();ws=null;closeTermWindow();};
  ws.onclose=()=>{resetBtn();ws=null;};
}
function disconnect(){
  if(ws){ws.close();ws=null;}
  closeTermWindow();
  if(term){term.dispose();term=null;}
  showToast(t('disconnected'),'⊗');
}
(function(){
  const savedTheme=localStorage.getItem('wssh-theme');
  if(savedTheme)setTheme(savedTheme,document.querySelector('[data-theme="'+savedTheme+'"]'));
  const savedUI=localStorage.getItem('wssh-uifont');
  if(savedUI){setUIFont(savedUI);document.getElementById('ui-font-select').value=savedUI;}
  const savedTerm=localStorage.getItem('wssh-termfont');
  if(savedTerm){currentTermFont=savedTerm;document.getElementById('term-font-select').value=savedTerm;}
  applyLang();
})();
</script>
</body>
</html>`
