const DASHBOARD_HTML: &str = include_str!("../../dashboard.html");
const WARD_LOGO_DARK_SVG: &str = include_str!("../../assets/ward-logo-dark.svg");
const WARD_LOGO_TRANSPARENT_SVG: &str = include_str!("../../assets/ward-logo-transparent.svg");
const WARD_LOGO_DARK_PNG: &[u8] = include_bytes!("../../assets/ward-logo-dark.png");
const WARD_FAVICON_LIGHT_PNG: &[u8] = include_bytes!("../../assets/ward-favicon-light.png");

#[allow(dead_code)]
const LEGACY_OVERVIEW_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ward Dashboard</title>
<style>
  * { box-sizing: border-box; }
  :root {
    --bg: #0f1115;
    --panel: #171a20;
    --panel-2: #1d222a;
    --line: #2b323c;
    --text: #e7ecf2;
    --muted: #91a0ae;
    --faint: #64717f;
    --accent: #34d399;
    --blue: #60a5fa;
    --warn: #f59e0b;
    --danger: #fb7185;
    --radius: 8px;
    --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --mono: "SF Mono", "Cascadia Code", "Roboto Mono", monospace;
  }
  body {
    margin: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font: 13px/1.4 var(--font);
    overflow: hidden;
  }
  button, input { font: inherit; }
  .shell { display: grid; grid-template-columns: 260px 1fr; height: 100vh; }
  aside {
    border-right: 1px solid var(--line);
    background: #12151a;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .brand {
    height: 52px;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 16px;
    border-bottom: 1px solid var(--line);
    font-weight: 700;
    letter-spacing: 0;
  }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); }
  .project-list { overflow: auto; padding: 8px; }
  .project {
    width: 100%;
    text-align: left;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text);
    padding: 9px 10px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  .project:hover { background: var(--panel); }
  .project.active { background: var(--panel-2); border-color: var(--line); }
  .project-name { font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .project-path { color: var(--faint); font: 11px var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px; }
  main { display: grid; grid-template-rows: 52px 1fr; min-width: 0; }
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 0 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
  }
  .title { font-weight: 700; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .header-meta { margin-left: auto; color: var(--muted); font-size: 12px; display: flex; align-items: center; gap: 12px; }
  .btn {
    border: 1px solid var(--line);
    border-radius: 6px;
    background: #20252d;
    color: var(--text);
    padding: 5px 10px;
    cursor: pointer;
  }
  .btn:hover { border-color: var(--muted); }
  .content {
    display: grid;
    grid-template-columns: minmax(460px, 1fr) minmax(360px, 0.8fr);
    gap: 0;
    min-height: 0;
  }
  .left, .right { overflow: auto; padding: 16px 18px; }
  .right { border-left: 1px solid var(--line); background: #111419; }
  section { margin-bottom: 18px; }
  .section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  h2 { margin: 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }
  .subtle { color: var(--faint); font-size: 12px; }
  .panel {
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--panel);
    overflow: hidden;
  }
  .kv { display: grid; grid-template-columns: 140px 1fr; border-bottom: 1px solid var(--line); }
  .kv:last-child { border-bottom: 0; }
  .kv div { padding: 8px 10px; min-width: 0; }
  .kv div:first-child { color: var(--muted); }
  .mono { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; background: #15191f; position: sticky; top: 0; }
  tr:last-child td { border-bottom: 0; }
  .check { display: flex; align-items: center; gap: 6px; margin: 2px 0; color: var(--text); font-family: var(--mono); font-size: 12px; }
  .env-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 3px 10px; }
  .input-row { display: flex; gap: 8px; padding: 10px; border-top: 1px solid var(--line); }
  .input-row input { flex: 1; min-width: 0; background: #101318; color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 6px 8px; }
  .pill { display: inline-flex; align-items: center; min-height: 22px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 12px; }
  .pill.ok { color: var(--accent); border-color: rgba(52,211,153,.35); }
  .pill.warn { color: var(--warn); border-color: rgba(245,158,11,.35); }
  .events { max-height: 460px; overflow: auto; }
  .event-row { cursor: pointer; }
  .event-row:hover { background: #1b2027; }
  .kind { color: var(--blue); font-family: var(--mono); font-size: 11px; }
  pre { margin: 0; white-space: pre-wrap; word-break: break-word; font: 11px/1.45 var(--mono); color: var(--muted); }
  @media (max-width: 900px) {
    body { overflow: auto; }
    .shell, main, .content { display: block; height: auto; }
    aside { border-right: 0; border-bottom: 1px solid var(--line); }
    .project-list { display: flex; overflow-x: auto; }
    .project { min-width: 220px; }
    .right { border-left: 0; border-top: 1px solid var(--line); }
  }
</style>
</head>
<body>
<div class="shell">
  <aside>
    <div class="brand"><span class="status-dot"></span><span>Ward Dashboard</span></div>
    <div class="project-list" id="projects"></div>
  </aside>
  <main>
    <header>
      <div class="title" id="title">Projects</div>
      <div class="header-meta">
        <span id="lastRefresh"></span>
        <button class="btn" id="refresh">Refresh</button>
      </div>
    </header>
    <div class="content">
      <div class="left">
        <section>
          <div class="section-head"><h2>Project</h2><span class="pill" id="configState">-</span></div>
          <div class="panel" id="projectMeta"></div>
        </section>
        <section>
          <div class="section-head"><h2>Profile Env Policy</h2><span class="subtle" id="vaultState"></span></div>
          <div class="panel" id="profiles"></div>
        </section>
      </div>
      <div class="right">
        <section>
          <div class="section-head"><h2>Runtime</h2><span class="pill" id="brokerState">-</span></div>
          <div class="panel" id="runtime"></div>
        </section>
        <section>
          <div class="section-head"><h2>Logs</h2><span class="subtle" id="eventCount"></span></div>
          <div class="panel events"><table><thead><tr><th>Time</th><th>Kind</th><th>Event</th></tr></thead><tbody id="events"></tbody></table></div>
        </section>
        <section>
          <div class="section-head"><h2>Event Detail</h2></div>
          <div class="panel" style="padding:10px"><pre id="eventDetail">Select an event</pre></div>
        </section>
      </div>
    </div>
  </main>
</div>
<script>
const token = new URLSearchParams(location.search).get('token') || '';
let projects = [];
let status = null;
let events = [];
let selectedProject = null;

function withToken(path) {
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}token=${encodeURIComponent(token)}`;
}

async function api(path, options = {}) {
  const response = await fetch(withToken(path), {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function load() {
  [projects, status] = await Promise.all([
    api('/api/projects'),
    api('/api/dashboard/status')
  ]);
  if (!selectedProject && projects.length) {
    selectedProject = (projects.find(p => p.active) || projects[0]).name;
  }
  await loadEvents();
  render();
}

async function loadEvents() {
  const suffix = selectedProject ? `?project=${encodeURIComponent(selectedProject)}` : '';
  events = await api(`/api/events${suffix}`);
}

function render() {
  renderProjects();
  renderProject();
  renderRuntime();
  renderEvents();
  document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
}

function currentProject() {
  return projects.find(p => p.name === selectedProject) || projects[0] || null;
}

function renderProjects() {
  const host = document.getElementById('projects');
  host.innerHTML = '';
  projects.forEach(project => {
    const btn = document.createElement('button');
    btn.className = `project ${project.name === selectedProject ? 'active' : ''}`;
    btn.innerHTML = `<div class="project-name">${esc(project.name)}</div><div class="project-path">${esc(project.path)}</div>`;
    btn.addEventListener('click', async () => {
      selectedProject = project.name;
      await loadEvents();
      render();
    });
    host.appendChild(btn);
  });
}

function renderProject() {
  const project = currentProject();
  document.getElementById('title').textContent = project ? project.name : 'Projects';
  if (!project) {
    document.getElementById('projectMeta').innerHTML = '<div class="kv"><div>Status</div><div>No projects registered</div></div>';
    document.getElementById('profiles').innerHTML = '';
    return;
  }
  document.getElementById('configState').textContent = project.configStatus;
  document.getElementById('configState').className = `pill ${project.configStatus === 'ok' ? 'ok' : 'warn'}`;
  document.getElementById('vaultState').textContent = project.vaultKeysVerified ? 'vault keys verified' : 'vault keys unavailable';
  document.getElementById('projectMeta').innerHTML = [
    kv('path', project.path),
    kv('vault', project.vault),
    kv('broker session', project.brokerSessionActive ? 'active' : 'inactive'),
    kv('env names', String(project.envNames.length))
  ].join('');
  renderProfiles(project);
}

function renderProfiles(project) {
  const host = document.getElementById('profiles');
  if (!project.profiles.length) {
    host.innerHTML = '<div class="kv"><div>Profiles</div><div>None</div></div>';
    return;
  }
  host.innerHTML = project.profiles.map(profile => `
    <div style="border-bottom:1px solid var(--line)">
      <div class="kv"><div>${esc(profile.name)}</div><div class="mono">${esc(profile.command)}</div></div>
      <div style="padding:10px">
        <div class="env-grid">
          ${project.envNames.map(name => checkbox(project.name, profile.name, name, profile.env.includes(name))).join('')}
        </div>
      </div>
      <div class="input-row">
        <input data-add-env="${esc(project.name)}:${esc(profile.name)}" placeholder="ENV_NAME">
        <button class="btn" data-add-btn="${esc(project.name)}:${esc(profile.name)}">Add</button>
      </div>
    </div>
  `).join('');
  host.querySelectorAll('input[type="checkbox"]').forEach(input => {
    input.addEventListener('change', () => toggleEnv(project.name, input.dataset.profile, input.dataset.env, input.checked));
  });
  host.querySelectorAll('[data-add-btn]').forEach(btn => {
    btn.addEventListener('click', () => {
      const [projectName, profileName] = btn.dataset.addBtn.split(':');
      const input = host.querySelector(`[data-add-env="${cssEsc(projectName)}:${cssEsc(profileName)}"]`);
      addEnv(projectName, profileName, input.value);
      input.value = '';
    });
  });
}

function checkbox(project, profile, env, checked) {
  return `<label class="check"><input type="checkbox" data-project="${esc(project)}" data-profile="${esc(profile)}" data-env="${esc(env)}" ${checked ? 'checked' : ''}>${esc(env)}</label>`;
}

async function toggleEnv(projectName, profileName, envName, enabled) {
  const project = projects.find(p => p.name === projectName);
  const profile = project.profiles.find(p => p.name === profileName);
  const env = new Set(profile.env);
  enabled ? env.add(envName) : env.delete(envName);
  await saveProfileEnv(projectName, profileName, [...env]);
}

async function addEnv(projectName, profileName, envName) {
  envName = envName.trim();
  if (!envName) return;
  const project = projects.find(p => p.name === projectName);
  const profile = project.profiles.find(p => p.name === profileName);
  const env = new Set([...profile.env, envName]);
  await saveProfileEnv(projectName, profileName, [...env]);
}

async function saveProfileEnv(projectName, profileName, env) {
  const updated = await api(`/api/projects/${encodeURIComponent(projectName)}/profiles/${encodeURIComponent(profileName)}/env`, {
    method: 'PATCH',
    body: JSON.stringify({ env })
  });
  projects = projects.map(project => project.name === projectName ? updated : project);
  renderProject();
}

function renderRuntime() {
  const broker = status && status.broker;
  document.getElementById('brokerState').textContent = broker && broker.running ? 'broker active' : 'broker inactive';
  document.getElementById('brokerState').className = `pill ${broker && broker.running ? 'ok' : 'warn'}`;
  const rows = [];
  rows.push(kv('dashboards', String((status && status.instances || []).length)));
  rows.push(kv('guardian', status && status.human.guardianSocketExists ? 'active' : 'inactive'));
  rows.push(kv('shell pid', status ? String(status.human.shellPid) : '-'));
  rows.push(kv('sessions', broker ? String(broker.sessions.length) : '0'));
  document.getElementById('runtime').innerHTML = rows.join('');
}

function renderEvents() {
  document.getElementById('eventCount').textContent = `${events.length} events`;
  const body = document.getElementById('events');
  body.innerHTML = events.slice(0, 250).map((event, index) => {
    const payload = event.payload || event;
    const label = payload.eventType || payload.requestedCommand || payload.declaredAction || payload.status || '-';
    return `<tr class="event-row" data-event-index="${index}">
      <td class="mono">${esc((event.timestamp || '').slice(11, 19))}</td>
      <td class="kind">${esc(event._kind || '-')}</td>
      <td>${esc(String(label))}</td>
    </tr>`;
  }).join('');
  body.querySelectorAll('.event-row').forEach(row => {
    row.addEventListener('click', () => {
      const event = events[Number(row.dataset.eventIndex)];
      document.getElementById('eventDetail').textContent = JSON.stringify(event, null, 2);
    });
  });
}

function kv(label, value) {
  return `<div class="kv"><div>${esc(label)}</div><div class="mono">${esc(value)}</div></div>`;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function cssEsc(value) {
  return String(value).replace(/["\\]/g, '\\$&');
}

document.getElementById('refresh').addEventListener('click', load);
load().catch(error => {
  document.getElementById('title').textContent = 'Dashboard error';
  document.getElementById('projectMeta').innerHTML = `<div class="kv"><div>Error</div><div>${esc(error.message)}</div></div>`;
});
</script>
</body>
</html>"##;
