const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
let token = '';
function node(tag: string, text = '', className = '') {
  const e = document.createElement(tag);
  e.textContent = text;
  e.className = className;
  return e;
}
function notice(message: string, error = false) {
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}
async function api(path: string, method = 'GET', body?: unknown, credential = token) {
  const response = await fetch(path, {
    method,
    headers: {
      authorization: `Bearer ${credential}`,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? 'request_failed');
  return data;
}
function error(e: unknown) {
  notice(e instanceof Error ? e.message : 'Request failed', true);
}
function value(id: string) {
  return $<HTMLInputElement>(id).value;
}
function cell(row: HTMLElement, text: string, cls = '') {
  const c = node('td', text, cls);
  row.append(c);
  return c;
}

let scenarios: any[] = [],
  run: any = null;
function showFinding(f: any) {
  $('finding-description').textContent = f.description;
  $('timeline-provider').textContent = `${f.provider} · ${f.technique}`;
  const timeline = $('timeline');
  timeline.replaceChildren();
  for (const e of f.evidence) {
    const item = node('div', '', 'timeline-event');
    item.append(
      node('small', e.time),
      node('p', e.action),
      node('h3', e.actor),
      node('small', `${e.outcome} · ${e.id}`),
    );
    timeline.append(item);
  }
}
function showRun(data: any) {
  run = data;
  $('event-count').textContent = String(data.eventCount);
  $('finding-count').textContent = String(data.findings.length);
  $('run-name').textContent = data.name;
  const list = $('finding-list');
  list.replaceChildren();
  list.className = data.findings.length ? '' : 'empty';
  if (!data.findings.length) {
    list.textContent = 'No findings. Inspect the scenario expectations to verify this result.';
    $('timeline').replaceChildren();
    $('finding-description').textContent = 'No detection evidence for this investigation.';
  }
  for (const f of data.findings) {
    const item = node('button', '', 'finding');
    const top = node('div', '', 'finding-top');
    top.append(node('h3', f.title), node('span', f.severity, 'badge ' + f.severity));
    item.append(
      top,
      node('p', `${f.actor} · ${f.evidence.length} evidence events`),
      node('small', `${f.provider.toUpperCase()} / ${f.ruleId} / v${f.ruleVersion}`),
    );
    item.onclick = () => showFinding(f);
    list.append(item);
  }
  if (data.findings.length) showFinding(data.findings[0]);
}
async function loadRuns() {
  const { runs } = await api('/api/runs');
  const select = $<HTMLSelectElement>('saved-runs');
  select.replaceChildren();
  for (const r of runs) {
    const option = node('option', `${r.name} · ${r.findings} findings`) as HTMLOptionElement;
    option.value = r.id;
    select.append(option);
  }
}
async function connect() {
  token = value('token');
  const me = await api('/api/me');
  $('status').textContent = `${me.agent} · ${me.role}`;
  const [ruleData, scenarioData, evaluation] = await Promise.all([
    api('/api/rules'),
    api('/api/scenarios'),
    api('/api/evaluation'),
  ]);
  scenarios = scenarioData;
  const select = $<HTMLSelectElement>('scenario');
  select.replaceChildren();
  for (const s of scenarios) {
    const o = node('option', s.id) as HTMLOptionElement;
    o.value = s.id;
    select.append(o);
  }
  select.onchange = () => {
    $('scenario-description').textContent =
      scenarios.find((s) => s.id === value('scenario'))?.description ?? '';
  };
  select.onchange(new Event('change'));
  $('rule-count').textContent = String(ruleData.rules.length);
  const body = $('rule-list');
  body.replaceChildren();
  for (const r of ruleData.rules) {
    const row = node('tr');
    const c = cell(row, '');
    c.append(node('b', r.title), node('small', `v${r.version} · ${r.severity}`));
    cell(row, r.kind);
    cell(row, r.windowSeconds + 's', 'mono');
    cell(row, r.technique, 'mono');
    body.append(row);
  }
  const pct = (x: number | null) => (x === null ? 'Undefined' : (x * 100).toFixed(1) + '%');
  $('checks').textContent =
    `${evaluation.rows.filter((r: any) => r.passed).length}/${evaluation.scenarios}`;
  $('precision').textContent = pct(evaluation.precision);
  $('recall').textContent = pct(evaluation.recall);
  $('false-positives').textContent = String(evaluation.fp);
  $('false-negatives').textContent = String(evaluation.fn);
  $('scope').textContent =
    `${evaluation.scenarios} scenarios × ${evaluation.rules} rules. Scope: synthetic fixtures.`;
  await loadRuns();
  notice(`Connected to ${me.tenant}. Choose a scenario or open a saved investigation.`);
}
$('connect').onclick = () => void connect().catch(error);
$('replay-button').onclick = () => {
  const s = scenarios.find((s) => s.id === value('scenario'));
  if (!s) {
    notice('Connect to load the scenario catalog.', true);
    return;
  }
  const button = $<HTMLButtonElement>('replay-button');
  button.disabled = true;
  void api('/api/replay', 'POST', { name: s.id, events: s.events })
    .then(async (data) => {
      showRun(data);
      await loadRuns();
      notice(
        `Replay complete: ${data.eventCount} events, ${data.findings.length} findings. Expected rules: ${s.expected.join(', ') || 'none'}.`,
      );
    })
    .catch(error)
    .finally(() => (button.disabled = false));
};
$('open-run').onclick = () => {
  const id = value('saved-runs');
  if (id)
    void api('/api/runs/' + encodeURIComponent(id))
      .then(showRun)
      .catch(error);
};
$('import-button').onclick = () => {
  const file = $<HTMLInputElement>('event-file').files?.[0];
  if (!file || file.size > 240000) {
    notice('Select a JSON batch smaller than 240 KB.', true);
    return;
  }
  void file
    .text()
    .then((text) =>
      api('/api/replay', 'POST', { name: 'Imported batch', events: JSON.parse(text) }),
    )
    .then(async (data) => {
      showRun(data);
      await loadRuns();
      notice('Imported batch validated and replayed.');
    })
    .catch(error);
};
$('export').onclick = () => {
  if (!run) {
    notice('Replay or open an investigation before exporting.', true);
    return;
  }
  const url = URL.createObjectURL(
      new Blob([JSON.stringify(run, null, 2)], { type: 'application/json' }),
    ),
    link = document.createElement('a');
  link.href = url;
  link.download = 'investigation.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
