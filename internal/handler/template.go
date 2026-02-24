package handler

// =====================================================================
//  SETUP PAGE
// =====================================================================
const setupHTMLTemplate = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>WebSSH — 初始设置</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&family=Noto+Sans+SC:wght@300;400;700&display=swap" rel="stylesheet">
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#fdf2ff;--surface:#fff;--surface2:#fdf5ff;--border:#ecd5f8;
      --accent:#a855f7;--accent2:#ec4899;--accent-glow:rgba(168,85,247,0.15);
      --text:#2d1040;--text-muted:#9b7ab0;--error:#ef4444;--success:#10b981;
      --shadow:0 4px 24px rgba(168,85,247,0.12);--shadow-lg:0 16px 56px rgba(168,85,247,0.18);
      --radius:14px;--font:'Outfit','Noto Sans SC',sans-serif;
    }
    html,body{min-height:100%;background:var(--bg);font-family:var(--font);color:var(--text);}
    .bg-mesh{position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:0;}
    .bg-mesh::before{content:'';position:absolute;width:130%;height:130%;top:-15%;left:-15%;
      background:radial-gradient(ellipse 65% 55% at 25% 35%,rgba(168,85,247,0.14),transparent 55%),
                 radial-gradient(ellipse 55% 65% at 75% 65%,rgba(236,72,153,0.10),transparent 55%);
      animation:float 12s ease-in-out infinite alternate;}
    @keyframes float{from{transform:translate(0,0) scale(1);}to{transform:translate(18px,-16px) scale(1.05);}}
    .page{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;}
    .card{width:100%;max-width:460px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
      padding:40px 40px 36px;box-shadow:var(--shadow-lg);position:relative;overflow:hidden;animation:up .6s cubic-bezier(.22,1,.36,1) both;}
    .card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
      background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:.85;}
    @keyframes up{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
    .header{text-align:center;margin-bottom:32px;}
    .icon{width:60px;height:60px;border-radius:18px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      display:flex;align-items:center;justify-content:center;margin:0 auto 16px;box-shadow:0 8px 24px var(--accent-glow);}
    h1{font-size:1.6rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:6px;}
    .sub{font-size:.82rem;color:var(--text-muted);}
    .alert{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:9px;
      padding:10px 14px;color:#dc2626;font-size:.82rem;margin-bottom:18px;display:flex;align-items:center;gap:8px;}
    .field{margin-bottom:18px;}
    label{display:block;font-size:.68rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
      color:var(--text-muted);margin-bottom:7px;}
    .input-wrap{position:relative;display:flex;align-items:center;}
    .input-icon{position:absolute;left:13px;color:var(--text-muted);pointer-events:none;transition:color .2s;}
    input[type=text],input[type=password]{width:100%;padding:12px 14px 12px 40px;
      background:var(--surface2);border:1.5px solid var(--border);border-radius:9px;
      font-family:var(--font);font-size:.9rem;color:var(--text);outline:none;
      transition:border-color .2s,box-shadow .2s;}
    input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
    input:focus+.input-icon, .input-wrap:focus-within .input-icon{color:var(--accent);}
    input::placeholder{color:var(--text-muted);opacity:.6;}
    .btn{width:100%;padding:13px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      border:none;border-radius:9px;color:#fff;font-family:var(--font);font-size:.95rem;font-weight:700;
      letter-spacing:.04em;cursor:pointer;transition:opacity .2s,transform .15s;
      box-shadow:0 4px 16px var(--accent-glow);margin-top:8px;}
    .btn:hover{opacity:.9;transform:translateY(-2px);}
    .btn:active{transform:translateY(0);}
    .hint{font-size:.73rem;color:var(--text-muted);text-align:center;margin-top:16px;line-height:1.6;}
    @media(max-width:480px){.card{padding:28px 20px 24px;}.page{padding:16px 12px;}}
  </style>
</head>
<body>
<div class="bg-mesh"></div>
<div class="page">
  <div class="card">
    <div class="header">
      <div class="icon">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <h1>初始账户设置</h1>
      <p class="sub">首次运行 · 请设置登录凭据</p>
    </div>
    {{if .Error}}<div class="alert"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>{{.Error}}</div>{{end}}
    <form method="POST" action="/setup" autocomplete="off">
      <div class="field">
        <label>用户名</label>
        <div class="input-wrap">
          <svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <input type="text" name="username" placeholder="设置用户名" required autocomplete="off"/>
        </div>
      </div>
      <div class="field">
        <label>密码</label>
        <div class="input-wrap">
          <svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" name="password" placeholder="设置密码（至少6位）" required autocomplete="new-password"/>
        </div>
      </div>
      <div class="field">
        <label>确认密码</label>
        <div class="input-wrap">
          <svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" name="confirm" placeholder="再次输入密码" required autocomplete="new-password"/>
        </div>
      </div>
      <button type="submit" class="btn">完成设置 →</button>
    </form>
    <p class="hint">此设置仅需完成一次，凭据将安全保存在本地 data 目录中</p>
  </div>
</div>
</body>
</html>`

// =====================================================================
//  LOGIN PAGE
// =====================================================================
const loginHTMLTemplate = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>WebSSH — 登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&family=Noto+Sans+SC:wght@300;400;700&display=swap" rel="stylesheet">
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#fdf2ff;--surface:#fff;--surface2:#fdf5ff;--border:#ecd5f8;
      --accent:#a855f7;--accent2:#ec4899;--accent-glow:rgba(168,85,247,0.15);
      --text:#2d1040;--text-muted:#9b7ab0;--error:#ef4444;--success:#10b981;
      --shadow-lg:0 16px 56px rgba(168,85,247,0.18);--radius:14px;
      --font:'Outfit','Noto Sans SC',sans-serif;
    }
    html,body{min-height:100%;background:var(--bg);font-family:var(--font);color:var(--text);}
    .bg-mesh{position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:0;}
    .bg-mesh::before{content:'';position:absolute;width:130%;height:130%;top:-15%;left:-15%;
      background:radial-gradient(ellipse 65% 55% at 25% 35%,rgba(168,85,247,0.14),transparent 55%),
                 radial-gradient(ellipse 55% 65% at 75% 65%,rgba(236,72,153,0.10),transparent 55%);
      animation:float 12s ease-in-out infinite alternate;}
    @keyframes float{from{transform:translate(0,0) scale(1);}to{transform:translate(18px,-16px) scale(1.05);}}
    .page{position:relative;z-index:1;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;}
    .card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
      padding:40px 36px 36px;box-shadow:var(--shadow-lg);position:relative;overflow:hidden;animation:up .6s cubic-bezier(.22,1,.36,1) both;}
    .card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
      background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:.85;}
    @keyframes up{from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);}}
    .header{text-align:center;margin-bottom:28px;}
    .icon{width:56px;height:56px;border-radius:16px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      display:flex;align-items:center;justify-content:center;margin:0 auto 14px;box-shadow:0 8px 24px rgba(168,85,247,0.25);}
    h1{font-size:1.55rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:5px;}
    .sub{font-size:.8rem;color:var(--text-muted);}
    .alert{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:8px;
      padding:10px 13px;color:#dc2626;font-size:.82rem;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
    .success-msg{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25);border-radius:8px;
      padding:10px 13px;color:#059669;font-size:.82rem;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
    .field{margin-bottom:16px;}
    label{display:block;font-size:.67rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
      color:var(--text-muted);margin-bottom:7px;}
    .input-wrap{position:relative;display:flex;align-items:center;}
    .input-icon{position:absolute;left:13px;color:var(--text-muted);pointer-events:none;transition:color .2s;}
    input[type=text],input[type=password]{width:100%;padding:12px 14px 12px 40px;
      background:var(--surface2);border:1.5px solid var(--border);border-radius:9px;
      font-family:var(--font);font-size:.9rem;color:var(--text);outline:none;
      transition:border-color .2s,box-shadow .2s;}
    input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(168,85,247,0.12);}
    .input-wrap:focus-within .input-icon{color:var(--accent);}
    input::placeholder{color:var(--text-muted);opacity:.6;}
    .btn{width:100%;padding:13px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      border:none;border-radius:9px;color:#fff;font-family:var(--font);font-size:.95rem;font-weight:700;
      letter-spacing:.04em;cursor:pointer;transition:opacity .2s,transform .15s;
      box-shadow:0 4px 16px rgba(168,85,247,0.25);margin-top:6px;}
    .btn:hover{opacity:.9;transform:translateY(-2px);}
    .btn:active{transform:translateY(0);}
    @media(max-width:480px){.card{padding:28px 18px 24px;}}
  </style>
</head>
<body>
<div class="bg-mesh"></div>
<div class="page">
  <div class="card">
    <div class="header">
      <div class="icon">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
        </svg>
      </div>
      <h1>WebSSH Console</h1>
      <p class="sub">请登录以继续</p>
    </div>
    {{if .Success}}<div class="success-msg"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>账户设置成功，请登录</div>{{end}}
    {{if .Error}}<div class="alert"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>{{.Error}}</div>{{end}}
    <form method="POST" action="/login">
      <div class="field">
        <label>用户名</label>
        <div class="input-wrap">
          <svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <input type="text" name="username" placeholder="用户名" required/>
        </div>
      </div>
      <div class="field">
        <label>密码</label>
        <div class="input-wrap">
          <svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input type="password" name="password" placeholder="密码" required/>
        </div>
      </div>
      <button type="submit" class="btn">登录</button>
    </form>
  </div>
</div>
</body>
</html>`

// =====================================================================
//  MAIN APP PAGE
// =====================================================================
const indexHTMLTemplate = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover"/>
  <meta name="apple-mobile-web-app-capable" content="yes"/>
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
  <title>WebSSH Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@300;400;600;700;800&family=Noto+Sans+SC:wght@300;400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css"/>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
    :root{
      --bg:#fdf2ff;--bg2:#f9eaff;
      --surface:#fff;--surface2:#fdf5ff;
      --border:#ecd5f8;
      --accent:#a855f7;--accent2:#ec4899;
      --accent-glow:rgba(168,85,247,0.14);
      --text:#2d1040;--text-muted:#9b7ab0;
      --success:#10b981;--error:#ef4444;--warn:#f59e0b;
      --shadow:0 4px 24px rgba(168,85,247,0.10);
      --shadow-lg:0 16px 56px rgba(168,85,247,0.16);
      --radius:14px;
      --font-ui:'Outfit','Noto Sans SC',sans-serif;
      --font-mono:'JetBrains Mono',monospace;
    }
    [data-theme="blue-white"]{
      --bg:#f0f4ff;--surface:#fff;--surface2:#f5f7ff;--border:#dde3f5;
      --accent:#3b6bff;--accent2:#7c3aed;--accent-glow:rgba(59,107,255,0.14);
      --text:#1a2040;--text-muted:#7a88b0;
      --shadow:0 4px 24px rgba(59,107,255,0.09);--shadow-lg:0 16px 56px rgba(59,107,255,0.14);
    }
    [data-theme="dark-blue"]{
      --bg:#080e1e;--surface:#111827;--surface2:#1a2236;--border:#1e2d45;
      --accent:#00d4ff;--accent2:#7c3aed;--accent-glow:rgba(0,212,255,0.11);
      --text:#e2e8f0;--text-muted:#64748b;
      --shadow:0 4px 24px rgba(0,0,0,0.35);--shadow-lg:0 16px 56px rgba(0,0,0,0.5);
    }
    [data-theme="forest"]{
      --bg:#f0faf4;--surface:#fff;--surface2:#f5fdf8;--border:#c8e6d4;
      --accent:#059669;--accent2:#0891b2;--accent-glow:rgba(5,150,105,0.11);
      --text:#0f2a1e;--text-muted:#6b9e82;
      --shadow:0 4px 24px rgba(5,150,105,0.09);--shadow-lg:0 16px 56px rgba(5,150,105,0.14);
    }
    html,body{height:100%;}
    body{background:var(--bg);color:var(--text);font-family:var(--font-ui);min-height:100vh;
      transition:background .4s,color .4s;-webkit-text-size-adjust:100%;}
    .bg-mesh{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden;}
    .bg-mesh::before{content:'';position:absolute;width:120%;height:120%;top:-10%;left:-10%;
      background:radial-gradient(ellipse 60% 50% at 20% 30%,var(--accent-glow),transparent 55%),
                 radial-gradient(ellipse 50% 60% at 80% 70%,rgba(124,58,237,0.07),transparent 55%);
      animation:meshFloat 14s ease-in-out infinite alternate;}
    @keyframes meshFloat{from{transform:translate(0,0) scale(1);}to{transform:translate(20px,-18px) scale(1.06);}}

    .page{position:relative;z-index:1;min-height:100vh;display:flex;flex-direction:column;
      align-items:center;justify-content:center;padding:60px 16px 24px;}
    @media(max-width:600px){.page{padding:56px 12px 16px;justify-content:flex-start;padding-top:64px;}}

    /* ---- TOPBAR ---- */
    .topbar{position:fixed;top:0;left:0;right:0;z-index:100;display:flex;align-items:center;
      justify-content:space-between;padding:10px 16px;
      background:rgba(255,255,255,0.6);backdrop-filter:blur(14px);
      border-bottom:1px solid var(--border);}
    @media(prefers-color-scheme:dark){.topbar{background:rgba(17,24,39,0.7);}}
    [data-theme="dark-blue"] .topbar{background:rgba(8,14,30,0.8);}
    .topbar-left{display:flex;align-items:center;gap:10px;}
    .topbar-logo{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      display:flex;align-items:center;justify-content:center;flex-shrink:0;}
    .topbar-title{font-weight:700;font-size:.9rem;color:var(--text);display:none;}
    @media(min-width:400px){.topbar-title{display:block;}}
    .topbar-right{display:flex;align-items:center;gap:8px;}
    .btn-icon{width:36px;height:36px;border-radius:50%;border:1px solid var(--border);background:var(--surface);
      color:var(--text-muted);cursor:pointer;display:flex;align-items:center;justify-content:center;
      box-shadow:var(--shadow);transition:all .2s;backdrop-filter:blur(10px);flex-shrink:0;}
    .btn-icon:hover{color:var(--accent);border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
    .btn-icon.spin:hover{transform:rotate(60deg);}
    .btn-logout{font-size:.72rem;padding:0 12px;width:auto;border-radius:8px;gap:5px;font-family:var(--font-ui);font-weight:600;white-space:nowrap;}

    /* ---- HEADER ---- */
    .header{text-align:center;margin-bottom:18px;animation:fadeDown .7s cubic-bezier(.22,1,.36,1) both;}
    .header-title-row{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:5px;}
    .header-icon{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      display:flex;align-items:center;justify-content:center;flex-shrink:0;
      box-shadow:0 6px 20px var(--accent-glow);animation:iconBob 3.5s ease-in-out infinite;}
    @keyframes iconBob{0%,100%{transform:translateY(0);}50%{transform:translateY(-5px);}}
    .header h1{font-size:clamp(1.4rem,5vw,2.2rem);font-weight:800;letter-spacing:-.03em;
      background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
    .subtitle{font-family:var(--font-mono);font-size:.65rem;color:var(--text-muted);letter-spacing:.2em;text-transform:uppercase;}
    .pill-bar{display:flex;align-items:center;justify-content:center;gap:10px;margin-top:8px;flex-wrap:wrap;}
    .pill{display:inline-flex;align-items:center;gap:5px;padding:3px 11px;border-radius:100px;
      background:var(--surface);border:1px solid var(--border);font-size:.67rem;color:var(--text-muted);
      font-family:var(--font-mono);}
    .pill-dot{width:6px;height:6px;border-radius:50%;background:var(--success);animation:pulse 2s ease-in-out infinite;}
    @keyframes pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:.5;transform:scale(.8);}}

    /* ---- CARD ---- */
    .card{width:100%;max-width:660px;background:var(--surface);border:1px solid var(--border);
      border-radius:var(--radius);padding:28px 32px;box-shadow:var(--shadow-lg);position:relative;overflow:hidden;
      animation:fadeUp .7s cubic-bezier(.22,1,.36,1) .1s both;backdrop-filter:blur(20px);}
    .card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
      background:linear-gradient(90deg,transparent,var(--accent) 40%,var(--accent2) 70%,transparent);}
    @media(max-width:600px){.card{padding:18px 14px;border-radius:12px;}}

    /* ---- FORM GRID ---- */
    .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
    @media(max-width:540px){.form-grid{grid-template-columns:1fr;gap:12px;}}
    .field{display:flex;flex-direction:column;gap:6px;}
    .field.full{grid-column:1 / -1;}
    label{font-size:.65rem;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--text-muted);}
    label .req{color:var(--accent);margin-left:2px;}
    .input-wrap{position:relative;display:flex;align-items:center;}
    .input-icon{position:absolute;left:11px;color:var(--text-muted);pointer-events:none;transition:color .2s;}
    input[type=text],input[type=password],input[type=number]{
      width:100%;padding:10px 13px 10px 36px;background:var(--surface2);border:1.5px solid var(--border);
      border-radius:8px;font-family:var(--font-mono);font-size:.85rem;color:var(--text);outline:none;
      transition:border-color .2s,box-shadow .2s;-webkit-appearance:none;appearance:none;}
    input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
    .input-wrap:focus-within .input-icon{color:var(--accent);}
    input::placeholder{color:var(--text-muted);opacity:.6;}

    /* ---- AUTH TABS ---- */
    .auth-tabs{display:flex;background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;padding:3px;gap:2px;width:fit-content;}
    .auth-tab{padding:6px 16px;border:none;background:transparent;color:var(--text-muted);
      font-family:var(--font-ui);font-size:.78rem;font-weight:600;cursor:pointer;border-radius:6px;transition:all .2s;white-space:nowrap;}
    .auth-tab.active{background:var(--surface);color:var(--accent);box-shadow:0 2px 8px rgba(0,0,0,0.08);}
    .auth-pane{display:none;grid-column:1 / -1;}
    .auth-pane.active{display:contents;}

    /* ---- FILE PICKER ---- */
    .file-wrap{display:flex;align-items:center;background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;overflow:hidden;transition:border-color .2s;}
    .file-wrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
    .file-btn{background:transparent;border:none;border-right:1.5px solid var(--border);padding:9px 13px;
      font-family:var(--font-mono);font-size:.7rem;color:var(--accent);cursor:pointer;display:flex;align-items:center;gap:5px;transition:background .2s;white-space:nowrap;}
    .file-btn:hover{background:var(--accent-glow);}
    .file-name{flex:1;padding:9px 11px;font-family:var(--font-mono);font-size:.73rem;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    #private-key-file{display:none;}

    /* ---- STORE ACTION BUTTONS ---- */
    .store-actions{display:flex;gap:8px;grid-column:1 / -1;}
    .btn-secondary{flex:1;padding:9px 12px;background:var(--surface2);border:1.5px solid var(--border);
      border-radius:8px;color:var(--text-muted);font-family:var(--font-ui);font-size:.8rem;font-weight:600;
      cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px;}
    .btn-secondary:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-glow);}

    /* ---- CONNECT BUTTON ---- */
    .btn-connect{grid-column:1 / -1;padding:12px 28px;
      background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%);
      border:none;border-radius:8px;color:#fff;font-family:var(--font-ui);font-size:.92rem;font-weight:700;
      letter-spacing:.04em;cursor:pointer;transition:opacity .2s,transform .15s,box-shadow .2s;
      display:flex;align-items:center;justify-content:center;gap:8px;
      box-shadow:0 4px 16px var(--accent-glow);position:relative;overflow:hidden;}
    .btn-connect::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.12),transparent);pointer-events:none;}
    .btn-connect:hover:not(:disabled){opacity:.9;transform:translateY(-2px);box-shadow:0 8px 24px var(--accent-glow);}
    .btn-connect:active:not(:disabled){transform:translateY(0);}
    .btn-connect:disabled{opacity:.42;cursor:not-allowed;}

    /* ---- SETTINGS MODAL ---- */
    .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.25);backdrop-filter:blur(6px);z-index:200;
      display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;transition:opacity .25s;padding:16px;}
    .modal-backdrop.open{opacity:1;pointer-events:all;}
    .modal{width:100%;max-width:440px;background:var(--surface);border:1px solid var(--border);border-radius:16px;
      box-shadow:var(--shadow-lg);overflow:hidden;transform:scale(.95) translateY(10px);
      transition:transform .25s cubic-bezier(.22,1,.36,1);max-height:90vh;display:flex;flex-direction:column;}
    .modal-backdrop.open .modal{transform:scale(1) translateY(0);}
    .modal-header{display:flex;align-items:center;justify-content:space-between;padding:18px 22px 14px;border-bottom:1px solid var(--border);flex-shrink:0;}
    .modal-title{font-size:.95rem;font-weight:700;color:var(--text);}
    .modal-close{width:30px;height:30px;border-radius:50%;border:1px solid var(--border);background:var(--surface2);
      color:var(--text-muted);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;flex-shrink:0;}
    .modal-close:hover{color:var(--error);border-color:var(--error);}
    .modal-body{padding:18px 22px 24px;display:flex;flex-direction:column;gap:18px;overflow-y:auto;}
    .setting-group{display:flex;flex-direction:column;gap:8px;}
    .setting-label{font-size:.67rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted);}
    .color-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;}
    .color-swatch{padding:9px 4px;border-radius:9px;border:2px solid transparent;cursor:pointer;
      display:flex;flex-direction:column;align-items:center;gap:5px;font-size:.63rem;color:var(--text-muted);
      text-align:center;transition:all .2s;background:var(--surface2);}
    .color-swatch:hover{border-color:var(--border);}
    .color-swatch.active{border-color:var(--accent);color:var(--accent);}
    .swatch-dot{width:26px;height:26px;border-radius:50%;}
    .toggle-group{display:flex;background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;padding:3px;gap:2px;width:fit-content;}
    .toggle-btn{padding:5px 18px;border:none;background:transparent;color:var(--text-muted);
      font-family:var(--font-ui);font-size:.8rem;font-weight:600;cursor:pointer;border-radius:6px;transition:all .2s;}
    .toggle-btn.active{background:var(--surface);color:var(--accent);box-shadow:0 2px 8px rgba(0,0,0,0.08);}
    .font-select{width:100%;padding:9px 32px 9px 12px;background:var(--surface2);border:1.5px solid var(--border);
      border-radius:8px;color:var(--text);font-family:var(--font-ui);font-size:.83rem;outline:none;cursor:pointer;
      transition:border-color .2s;appearance:none;-webkit-appearance:none;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
      background-repeat:no-repeat;background-position:right 11px center;}
    .font-select:focus{border-color:var(--accent);}

    /* ---- SSH LIST MODAL ---- */
    .ssh-list{display:flex;flex-direction:column;gap:8px;max-height:320px;overflow-y:auto;}
    .ssh-item{display:flex;align-items:center;gap:10px;padding:11px 14px;background:var(--surface2);
      border:1.5px solid var(--border);border-radius:9px;cursor:pointer;transition:all .2s;}
    .ssh-item:hover{border-color:var(--accent);background:var(--accent-glow);}
    .ssh-item.selected{border-color:var(--accent);background:var(--accent-glow);}
    .ssh-item-icon{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));
      display:flex;align-items:center;justify-content:center;flex-shrink:0;}
    .ssh-item-info{flex:1;min-width:0;}
    .ssh-item-name{font-weight:600;font-size:.85rem;color:var(--text);margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .ssh-item-detail{font-family:var(--font-mono);font-size:.7rem;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .ssh-item-del{width:26px;height:26px;border-radius:6px;border:1px solid var(--border);background:transparent;
      color:var(--text-muted);cursor:pointer;display:flex;align-items:center;justify-content:center;
      transition:all .2s;flex-shrink:0;}
    .ssh-item-del:hover{color:var(--error);border-color:var(--error);background:rgba(239,68,68,.08);}
    .ssh-empty{text-align:center;padding:28px;color:var(--text-muted);font-size:.83rem;}
    .modal-footer{padding:14px 22px;border-top:1px solid var(--border);display:flex;gap:8px;flex-shrink:0;}
    .btn-small{flex:1;padding:9px;border:1.5px solid var(--border);border-radius:8px;background:var(--surface2);
      color:var(--text-muted);font-family:var(--font-ui);font-size:.82rem;font-weight:600;cursor:pointer;transition:all .2s;}
    .btn-small.primary{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent;color:#fff;}
    .btn-small:hover{border-color:var(--accent);color:var(--accent);}
    .btn-small.primary:hover{opacity:.9;}

    /* ---- TERMINAL WINDOW ---- */
    #term-window{display:none;position:fixed;inset:0;z-index:300;background:rgba(0,0,0,.45);
      backdrop-filter:blur(9px);align-items:center;justify-content:center;}
    #term-window.open{display:flex;animation:fadeIn .3s ease both;}
    .term-popup{width:calc(100vw - 32px);max-width:980px;height:calc(100vh - 60px);max-height:700px;
      background:#0d1117;border-radius:12px;border:1px solid #1e2d45;overflow:hidden;
      display:flex;flex-direction:column;box-shadow:0 32px 80px rgba(0,0,0,.65);
      animation:popIn .3s cubic-bezier(.22,1,.36,1) both;}
    @media(max-width:640px){
      #term-window{align-items:flex-end;padding:0;}
      .term-popup{width:100%;max-width:100%;height:calc(100% - env(safe-area-inset-top,0px));
        max-height:none;border-radius:16px 16px 0 0;border:none;
        animation:slideUp .3s cubic-bezier(.22,1,.36,1) both;}
      @keyframes slideUp{from{transform:translateY(100%);}to{transform:translateY(0);}}
    }
    @keyframes popIn{from{transform:scale(.93) translateY(20px);opacity:0;}to{transform:scale(1) translateY(0);opacity:1;}}
    .term-titlebar{display:flex;align-items:center;padding:8px 12px;background:#111827;border-bottom:1px solid #1e2d45;gap:8px;flex-shrink:0;}
    .term-status-dot{width:9px;height:9px;border-radius:50%;background:#28c840;flex-shrink:0;animation:pulse 2.5s ease-in-out infinite;}
    .term-title-text{font-family:var(--font-mono);font-size:.72rem;color:#94a3b8;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .btn-disc{display:flex;align-items:center;gap:5px;padding:5px 11px;background:transparent;
      border:1px solid #ef4444;border-radius:6px;color:#ef4444;font-family:var(--font-mono);
      font-size:.68rem;cursor:pointer;transition:all .2s;white-space:nowrap;flex-shrink:0;}
    .btn-disc:hover{background:#ef4444;color:#fff;}
    #terminal{flex:1;overflow:hidden;padding:3px;}

    /* ---- VIRTUAL KEYBOARD ---- */
    .vkb{display:none;flex-shrink:0;background:#1a2236;border-top:1px solid #1e2d45;
      padding:6px 8px;gap:5px;overflow-x:auto;scrollbar-width:none;
      padding-bottom:calc(6px + env(safe-area-inset-bottom,0px));}
    .vkb::-webkit-scrollbar{display:none;}
    .vkb.show{display:flex;}
    .vkb-btn{flex-shrink:0;padding:7px 13px;background:#0d1117;border:1px solid #2d3f5a;
      border-radius:6px;color:#94a3b8;font-family:var(--font-mono);font-size:.72rem;
      cursor:pointer;transition:all .15s;user-select:none;-webkit-user-select:none;
      -webkit-tap-highlight-color:transparent;touch-action:manipulation;}
    .vkb-btn:active{background:rgba(168,85,247,0.2);color:#c084fc;border-color:#a855f7;}

    /* ---- ANIMATIONS ---- */
    @keyframes fadeDown{from{opacity:0;transform:translateY(-16px);}to{opacity:1;transform:translateY(0);}}
    @keyframes fadeUp{from{opacity:0;transform:translateY(16px);}to{opacity:1;transform:translateY(0);}}
    @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
    .spinner{width:15px;height:15px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;}
    @keyframes spin{to{transform:rotate(360deg);}}
    .toast{position:fixed;bottom:calc(20px + env(safe-area-inset-bottom,0px));left:50%;transform:translateX(-50%) translateY(60px);
      background:var(--surface);border:1px solid var(--border);border-radius:100px;
      padding:8px 18px;font-size:.8rem;color:var(--text);box-shadow:var(--shadow-lg);
      z-index:500;transition:transform .3s cubic-bezier(.22,1,.36,1),opacity .25s;
      opacity:0;white-space:nowrap;display:flex;align-items:center;gap:7px;max-width:calc(100vw - 32px);}
    .toast.show{transform:translateX(-50%) translateY(0);opacity:1;}
  </style>
</head>
<body data-theme="purple-pink">
<div class="bg-mesh"></div>

<!-- Top Bar -->
<div class="topbar">
  <div class="topbar-left">
    <div class="topbar-logo">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
      </svg>
    </div>
    <span class="topbar-title">WebSSH Console</span>
  </div>
  <div class="topbar-right">
    {{if .AuthEnabled}}
    <button class="btn-icon btn-logout" onclick="location.href='/logout'" title="退出登录">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span>退出</span>
    </button>
    {{end}}
    <button class="btn-icon spin" onclick="openSettings()" title="设置">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="3"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
      </svg>
    </button>
  </div>
</div>

<!-- Main Content -->
<div class="page">
  <div class="header">
    <div class="header-title-row">
      <div class="header-icon">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
        </svg>
      </div>
      <h1>WebSSH Console</h1>
    </div>
    <p class="subtitle">Secure Shell in Your Browser</p>
    <div class="pill-bar">
      <span class="pill"><span class="pill-dot"></span><span>就绪</span></span>
      <span class="pill">
        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        加密传输
      </span>
    </div>
  </div>

  <div class="card">
    <div class="form-grid">

      {{if .StoreEnabled}}
      <!-- 主机名（仅store模式） -->
      <div class="field full">
        <label>主机名（备注）</label>
        <div class="input-wrap">
          <svg class="input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          <input type="text" id="conn-name" placeholder="给这个连接起个名字（可选）"/>
        </div>
      </div>
      {{end}}

      <div class="field">
        <label>主机地址 <span class="req">*</span></label>
        <div class="input-wrap">
          <svg class="input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          <input type="text" id="host" placeholder="192.168.1.1 或 example.com"/>
        </div>
      </div>
      <div class="field">
        <label>端口</label>
        <div class="input-wrap">
          <svg class="input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
          <input type="number" id="port" value="22" min="1" max="65535"/>
        </div>
      </div>
      <div class="field full">
        <label>用户名</label>
        <div class="input-wrap">
          <svg class="input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <input type="text" id="username" placeholder="root（默认）"/>
        </div>
      </div>

      <!-- Auth Tabs -->
      <div class="field full">
        <div class="auth-tabs">
          <button class="auth-tab active" data-tab="password">密码登录</button>
          <button class="auth-tab" data-tab="key">私钥登录</button>
        </div>
      </div>
      <div class="auth-pane active" id="pane-password">
        <div class="field full">
          <label>密码</label>
          <div class="input-wrap">
            <svg class="input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <input type="password" id="password" placeholder="请输入密码"/>
          </div>
        </div>
      </div>
      <div class="auth-pane" id="pane-key">
        <div class="field">
          <label>私钥文件</label>
          <div class="file-wrap">
            <button class="file-btn" onclick="document.getElementById('private-key-file').click()">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              选择文件
            </button>
            <span class="file-name" id="key-file-name">未选择私钥文件</span>
          </div>
          <input type="file" id="private-key-file"/>
        </div>
        <div class="field">
          <label>密钥口令</label>
          <div class="input-wrap">
            <svg class="input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
            <input type="password" id="passphrase" placeholder="如需密钥口令请输入"/>
          </div>
        </div>
      </div>

      {{if .StoreEnabled}}
      <!-- Store action buttons -->
      <div class="store-actions">
        <button class="btn-secondary" onclick="saveSSHProfile()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          保存
        </button>
        <button class="btn-secondary" onclick="openSSHList()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
          SSH 列表
        </button>
      </div>
      {{end}}

      <button class="btn-connect" id="btn-connect" onclick="connect()">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
        <span>连接</span>
      </button>
    </div>
  </div>
</div>

<!-- Terminal Window -->
<div id="term-window">
  <div class="term-popup">
    <div class="term-titlebar">
      <div class="term-status-dot"></div>
      <div class="term-title-text" id="term-title">terminal</div>
      <button class="btn-disc" onclick="disconnect()">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        断开连接
      </button>
    </div>
    <div id="terminal"></div>
    <div class="vkb" id="vkb">
      <button class="vkb-btn" ontouchend="e(event);sendCtrl('c')" onclick="sendCtrl('c')">Ctrl+C</button>
      <button class="vkb-btn" ontouchend="e(event);sendCtrl('z')" onclick="sendCtrl('z')">Ctrl+Z</button>
      <button class="vkb-btn" ontouchend="e(event);sendCtrl('d')" onclick="sendCtrl('d')">Ctrl+D</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('\t')" onclick="sendKey('\t')">Tab</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('\x1b[A')" onclick="sendKey('\x1b[A')">↑</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('\x1b[B')" onclick="sendKey('\x1b[B')">↓</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('\x1b[D')" onclick="sendKey('\x1b[D')">←</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('\x1b[C')" onclick="sendKey('\x1b[C')">→</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('-')" onclick="sendKey('-')">-</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('_')" onclick="sendKey('_')">_</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('/')" onclick="sendKey('/')">/</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('|')" onclick="sendKey('|')">|</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('~')" onclick="sendKey('~')">~</button>
      <button class="vkb-btn" ontouchend="e(event);sendKey('\x1b')" onclick="sendKey('\x1b')">ESC</button>
    </div>
  </div>
</div>

<!-- Settings Modal -->
<div class="modal-backdrop" id="settings-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">设置</span>
      <button class="modal-close" onclick="closeSettings()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="modal-body">
      <div class="setting-group">
        <div class="setting-label">主题色</div>
        <div class="color-grid">
          <div class="color-swatch active" data-theme="purple-pink" onclick="setTheme('purple-pink',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#a855f7,#ec4899)"></div>
            <span>紫粉</span>
          </div>
          <div class="color-swatch" data-theme="blue-white" onclick="setTheme('blue-white',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#3b6bff,#7c3aed)"></div>
            <span>蓝白</span>
          </div>
          <div class="color-swatch" data-theme="dark-blue" onclick="setTheme('dark-blue',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#00d4ff,#7c3aed)"></div>
            <span>黑蓝</span>
          </div>
          <div class="color-swatch" data-theme="forest" onclick="setTheme('forest',this)">
            <div class="swatch-dot" style="background:linear-gradient(135deg,#059669,#0891b2)"></div>
            <span>森绿</span>
          </div>
        </div>
      </div>
      <div class="setting-group">
        <div class="setting-label">语言</div>
        <div class="toggle-group">
          <button class="toggle-btn active" id="lang-zh" onclick="setLang('zh',this)">中文</button>
          <button class="toggle-btn" id="lang-en" onclick="setLang('en',this)">English</button>
        </div>
      </div>
      <div class="setting-group">
        <div class="setting-label">界面字体</div>
        <select class="font-select" id="ui-font-select" onchange="setUIFont(this.value)">
          <option value="'Outfit','Noto Sans SC',sans-serif">Outfit（默认）</option>
          <option value="'Noto Sans SC',sans-serif">Noto Sans SC</option>
          <option value="system-ui,sans-serif">系统字体</option>
          <option value="Georgia,serif">Georgia（衬线）</option>
        </select>
      </div>
      <div class="setting-group">
        <div class="setting-label">终端字体</div>
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

<!-- SSH List Modal (store mode only) -->
<div class="modal-backdrop" id="ssh-list-modal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">已保存的 SSH 连接</span>
      <button class="modal-close" onclick="closeSSHList()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="modal-body" style="padding-bottom:8px;">
      <div class="ssh-list" id="ssh-list-content">
        <div class="ssh-empty">暂无保存的连接</div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn-small" onclick="closeSSHList()">取消</button>
      <button class="btn-small primary" onclick="selectSSHProfile()">选择</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
// ---- Config injected from server ----
const STORE_ENABLED = {{if .StoreEnabled}}true{{else}}false{{end}};
const AUTH_ENABLED = {{if .AuthEnabled}}true{{else}}false{{end}};

// ---- i18n ----
const i18n = {
  zh: {
    err_host: '请填写主机地址', err_auth: '请提供密码或私钥',
    connecting: '正在连接', connected: '已连接', disconnected: '已断开连接', conn_error: '连接失败',
    save_ok: '连接已保存', save_err: '保存失败', load_err: '加载失败',
    del_confirm: '确认删除此连接？'
  },
  en: {
    err_host: 'Please enter a hostname', err_auth: 'Please provide password or key',
    connecting: 'Connecting to', connected: 'Connected to', disconnected: 'Disconnected', conn_error: 'Connection failed',
    save_ok: 'Profile saved', save_err: 'Save failed', load_err: 'Load failed',
    del_confirm: 'Delete this profile?'
  }
};
let currentLang = 'zh', currentTermFont = "'JetBrains Mono',monospace";
const t = k => (i18n[currentLang] || i18n.zh)[k] || k;

// ---- Theme ----
function setTheme(theme, el) {
  document.body.setAttribute('data-theme', theme);
  document.querySelectorAll('.color-swatch').forEach(s => s.classList.remove('active'));
  if (el) el.classList.add('active');
  saveSettings({ theme });
}
function setUIFont(font) {
  document.documentElement.style.setProperty('--font-ui', font);
  saveSettings({ ui_font: font });
}
function setTermFont(font) {
  currentTermFont = font;
  if (term) term.options.fontFamily = font;
  saveSettings({ term_font: font });
}
function setLang(lang, btn) {
  currentLang = lang;
  document.querySelectorAll('#lang-zh,#lang-en').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  saveSettings({ lang });
}

// ---- Settings persistence ----
let settingsCache = {};
async function loadSettings() {
  if (STORE_ENABLED) {
    try {
      const r = await fetch('/api/settings');
      if (r.ok) settingsCache = await r.json();
    } catch(e) {}
  } else {
    settingsCache = {
      theme: localStorage.getItem('wssh-theme') || 'purple-pink',
      ui_font: localStorage.getItem('wssh-uifont') || '',
      term_font: localStorage.getItem('wssh-termfont') || '',
      lang: localStorage.getItem('wssh-lang') || 'zh',
    };
  }
  applySettings();
}
async function saveSettings(partial) {
  settingsCache = Object.assign(settingsCache, partial);
  if (STORE_ENABLED) {
    try { await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(settingsCache)}); }
    catch(e){}
  } else {
    if (partial.theme) localStorage.setItem('wssh-theme', partial.theme);
    if (partial.ui_font) localStorage.setItem('wssh-uifont', partial.ui_font);
    if (partial.term_font) localStorage.setItem('wssh-termfont', partial.term_font);
    if (partial.lang) localStorage.setItem('wssh-lang', partial.lang);
  }
}
function applySettings() {
  const s = settingsCache;
  if (s.theme) {
    document.body.setAttribute('data-theme', s.theme);
    const sw = document.querySelector('.color-swatch[data-theme="'+s.theme+'"]');
    document.querySelectorAll('.color-swatch').forEach(x => x.classList.remove('active'));
    if (sw) sw.classList.add('active');
  }
  if (s.ui_font) {
    document.documentElement.style.setProperty('--font-ui', s.ui_font);
    const sel = document.getElementById('ui-font-select');
    if (sel) sel.value = s.ui_font;
  }
  if (s.term_font) {
    currentTermFont = s.term_font;
    const sel = document.getElementById('term-font-select');
    if (sel) sel.value = s.term_font;
  }
  if (s.lang) {
    currentLang = s.lang;
    const btn = document.getElementById('lang-'+s.lang);
    document.querySelectorAll('#lang-zh,#lang-en').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
  }
}

// ---- Modals ----
function openSettings() { document.getElementById('settings-modal').classList.add('open'); }
function closeSettings() { document.getElementById('settings-modal').classList.remove('open'); }
document.getElementById('settings-modal').addEventListener('click', e => { if(e.target===e.currentTarget) closeSettings(); });
document.getElementById('ssh-list-modal').addEventListener('click', e => { if(e.target===e.currentTarget) closeSSHList(); });

// ---- Auth Tabs ----
let currentTab = 'password', privateKeyData = '';
document.querySelectorAll('.auth-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    currentTab = btn.dataset.tab;
    document.querySelectorAll('.auth-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.auth-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('pane-'+currentTab).classList.add('active');
  });
});
const pkFile = document.getElementById('private-key-file');
if (pkFile) pkFile.addEventListener('change', e => {
  const file = e.target.files[0]; if (!file) return;
  document.getElementById('key-file-name').textContent = file.name;
  const reader = new FileReader();
  reader.onload = ev => { privateKeyData = ev.target.result; };
  reader.readAsText(file);
});

// ---- Toast ----
let toastTimer;
function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

// ---- SSH Profiles (store mode) ----
let sshProfiles = [], selectedProfileId = null;

async function loadSSHProfiles() {
  if (!STORE_ENABLED) return;
  try {
    const r = await fetch('/api/ssh');
    if (r.ok) sshProfiles = await r.json() || [];
  } catch(e) { showToast(t('load_err')); }
}

async function saveSSHProfile() {
  const host = document.getElementById('host').value.trim();
  if (!host) { showToast('⚠ ' + t('err_host')); return; }
  const nameEl = document.getElementById('conn-name');
  const name = (nameEl ? nameEl.value.trim() : '') || host;
  const port = parseInt(document.getElementById('port').value) || 22;
  const username = document.getElementById('username').value.trim() || 'root';
  const authType = currentTab;
  const password = authType === 'password' ? document.getElementById('password').value : '';
  const passphrase = authType === 'key' ? document.getElementById('passphrase').value : '';
  const profile = { name, host, port, username, auth_type: authType, password, private_key: authType === 'key' ? privateKeyData : '', passphrase };
  try {
    const r = await fetch('/api/ssh', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(profile) });
    if (r.ok) { sshProfiles = await r.json(); showToast('✓ ' + t('save_ok')); }
    else showToast('✗ ' + t('save_err'));
  } catch(e) { showToast('✗ ' + t('save_err')); }
}

async function deleteSSHProfile(id, ev) {
  ev.stopPropagation();
  if (!confirm(t('del_confirm'))) return;
  try {
    const r = await fetch('/api/ssh?id='+encodeURIComponent(id), {method:'DELETE'});
    if (r.ok) {
      sshProfiles = await r.json();
      if (selectedProfileId === id) selectedProfileId = null;
      renderSSHList();
    }
  } catch(e) {}
}

function renderSSHList() {
  const container = document.getElementById('ssh-list-content');
  if (!sshProfiles || sshProfiles.length === 0) {
    container.innerHTML = '<div class="ssh-empty">暂无保存的连接<br><small style="opacity:.6">填写信息后点击&quot;保存&quot;按钮即可</small></div>';
    return;
  }
  const svgServer = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
  const svgDel = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>';
  container.innerHTML = sshProfiles.map(function(p) {
    var sel = selectedProfileId === p.id ? ' selected' : '';
    var safeId = String(p.id).replace(/'/g, "\\'");
    return '<div class="ssh-item' + sel + '" onclick="selectProfile(\'' + safeId + '\')">' +
      '<div class="ssh-item-icon">' + svgServer + '</div>' +
      '<div class="ssh-item-info">' +
        '<div class="ssh-item-name">' + escHtml(p.name||p.host) + '</div>' +
        '<div class="ssh-item-detail">' + escHtml(p.username||'root') + '@' + escHtml(p.host) + ':' + (p.port||22) + '</div>' +
      '</div>' +
      '<button class="ssh-item-del" onclick="deleteSSHProfile(\'' + safeId + '\',event)" title="删除">' + svgDel + '</button>' +
    '</div>';
  }).join('');
}
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function selectProfile(id) {
  selectedProfileId = id;
  renderSSHList();
}

async function openSSHList() {
  await loadSSHProfiles();
  renderSSHList();
  document.getElementById('ssh-list-modal').classList.add('open');
}
function closeSSHList() { document.getElementById('ssh-list-modal').classList.remove('open'); }

function selectSSHProfile() {
  if (!selectedProfileId) { closeSSHList(); return; }
  const p = sshProfiles.find(x => x.id === selectedProfileId);
  if (!p) { closeSSHList(); return; }
  // Fill form
  const nameEl = document.getElementById('conn-name');
  if (nameEl) nameEl.value = p.name || '';
  document.getElementById('host').value = p.host || '';
  document.getElementById('port').value = p.port || 22;
  document.getElementById('username').value = p.username || '';
  // Switch tab
  const tab = p.auth_type === 'key' ? 'key' : 'password';
  document.querySelectorAll('.auth-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  document.querySelectorAll('.auth-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === 'pane-' + tab);
  });
  currentTab = tab;
  if (tab === 'password') document.getElementById('password').value = p.password || '';
  else { document.getElementById('passphrase').value = p.passphrase || ''; privateKeyData = p.private_key || ''; }
  closeSSHList();
  showToast('✓ 已加载：' + (p.name || p.host));
}

// ---- Terminal ----
let ws = null, term = null, fitAddon = null;
const isMobile = () => window.innerWidth <= 640;

function e(ev) { ev.preventDefault(); }

function sendKey(k) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:'input',data:k}));
  if (term) { term.focus(); requestAnimationFrame(() => term.focus()); }
}
function sendCtrl(c) { sendKey(String.fromCharCode(c.charCodeAt(0) - 96)); }

function updateVkb() {
  const vkb = document.getElementById('vkb');
  if (!vkb) return;
  const show = isMobile() && document.getElementById('term-window').classList.contains('open');
  vkb.classList.toggle('show', show);
}

function resetBtn() {
  const btn = document.getElementById('btn-connect');
  btn.disabled = false;
  btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg><span>连接</span>';
}

function initTerm() {
  if (term) term.dispose();
  document.getElementById('terminal').innerHTML = '';
  const mobile = isMobile();
  term = new Terminal({
    theme: {background:'#0d1117',foreground:'#e2e8f0',cursor:'#c084fc',selectionBackground:'rgba(168,85,247,0.25)',
      black:'#1a2236',red:'#ef4444',green:'#10b981',yellow:'#f59e0b',blue:'#a855f7',
      magenta:'#ec4899',cyan:'#c084fc',white:'#e2e8f0',
      brightBlack:'#334155',brightRed:'#f87171',brightGreen:'#34d399',brightYellow:'#fbbf24',
      brightBlue:'#c084fc',brightMagenta:'#f0abfc',brightCyan:'#e879f9',brightWhite:'#f8fafc'},
    fontFamily: currentTermFont,
    fontSize: mobile ? 13 : 14,
    lineHeight: 1.5,
    cursorBlink: true,
    cursorStyle: 'bar',
    scrollback: 5000,
    allowTransparency: true,
    rightClickSelectsWord: true,
  });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('terminal'));
  setTimeout(() => fitAddon.fit(), 80);
  term.onData(data => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:'input',data}));
  });
  if (mobile && navigator.clipboard) {
    term.onSelectionChange(() => {
      const sel = term.getSelection();
      if (sel) navigator.clipboard.writeText(sel).catch(() => {});
    });
  }
}

window.addEventListener('resize', () => {
  if (fitAddon) setTimeout(() => {
    fitAddon.fit();
    if (term && ws && ws.readyState === WebSocket.OPEN)
      ws.send(JSON.stringify({type:'resize',rows:term.rows,cols:term.cols}));
  }, 80);
  updateVkb();
});

function openTermWindow(label) {
  document.getElementById('term-title').textContent = label;
  document.getElementById('term-window').classList.add('open');
  updateVkb();
  setTimeout(() => {
    fitAddon && fitAddon.fit();
    term && term.focus();
    if (ws && ws.readyState === WebSocket.OPEN && term)
      ws.send(JSON.stringify({type:'resize',rows:term.rows,cols:term.cols}));
  }, 140);
}
function closeTermWindow() {
  document.getElementById('term-window').classList.remove('open');
  document.getElementById('vkb').classList.remove('show');
}

function connect() {
  const host = document.getElementById('host').value.trim();
  const port = parseInt(document.getElementById('port').value) || 22;
  const username = document.getElementById('username').value.trim() || 'root';
  if (!host) { showToast('⚠ ' + t('err_host')); return; }
  const password = currentTab === 'password' ? document.getElementById('password').value : '';
  const private_key = currentTab === 'key' ? privateKeyData : '';
  const passphrase = currentTab === 'key' ? document.getElementById('passphrase').value : '';
  if (!password && !private_key) { showToast('⚠ ' + t('err_auth')); return; }

  const btn = document.getElementById('btn-connect');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div><span>' + t('connecting') + ' ' + host + '</span>';

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(proto + '://' + location.host + '/ws');
  ws.onopen = () => ws.send(JSON.stringify({type:'connect',host,port,username,password,private_key,passphrase}));
  ws.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'connected') {
      resetBtn();
      const label = username + '@' + host + ':' + port;
      showToast('✓ ' + t('connected') + ': ' + label);
      initTerm();
      openTermWindow(label);
    } else if (msg.type === 'output') {
      if (term) term.write(msg.data);
    } else if (msg.type === 'error') {
      showToast('✗ ' + t('conn_error') + ': ' + msg.data);
      resetBtn(); if (ws) { ws.close(); ws = null; } closeTermWindow();
    } else if (msg.type === 'closed') {
      showToast('⊗ ' + t('disconnected'));
      resetBtn(); ws = null; closeTermWindow();
    }
  };
  ws.onerror = () => { showToast('✗ ' + t('conn_error')); resetBtn(); ws = null; closeTermWindow(); };
  ws.onclose = () => { resetBtn(); ws = null; };
}

function disconnect() {
  if (ws) { ws.close(); ws = null; }
  closeTermWindow();
  if (term) { term.dispose(); term = null; }
  showToast('⊗ ' + t('disconnected'));
}

// ---- Init ----
loadSettings();
</script>
</body>
</html>`
