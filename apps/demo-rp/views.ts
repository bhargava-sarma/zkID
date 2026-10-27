// The demo shop's pages: server-rendered HTML with one inline style sheet, in
// the holder app's look (frontend/src/App.css). No web fonts and no script
// except the request-QR page's poll.

import { GENDERS, type Disclosed, type Rules, type VerifyResult } from '../../packages/verifier-sdk/src/index.ts';

export type Session = { challenge?: string; result?: VerifyResult; account?: number; rules?: Rules };

// States and union territories as commonly written, for the rule and sample
// pickers. A rule must match the spelling on Aadhaar (case and spacing aside).
// "Dadra and Nagar Haveli and Daman and Diu" is missing: at 39 characters it is
// longer than the circuit can read (packages/circuit test).
export const STATES = [
  'Andaman and Nicobar Islands', 'Andhra Pradesh', 'Arunachal Pradesh', 'Assam', 'Bihar', 'Chandigarh', 'Chhattisgarh', 'Delhi', 'Goa',
  'Gujarat', 'Haryana', 'Himachal Pradesh', 'Jammu and Kashmir', 'Jharkhand', 'Karnataka', 'Kerala', 'Ladakh', 'Lakshadweep',
  'Madhya Pradesh', 'Maharashtra', 'Manipur', 'Meghalaya', 'Mizoram', 'Nagaland', 'Odisha', 'Puducherry', 'Punjab', 'Rajasthan',
  'Sikkim', 'Tamil Nadu', 'Telangana', 'Tripura', 'Uttar Pradesh', 'Uttarakhand', 'West Bengal',
];

export const escape = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const pinShown = (p: string) => p.padEnd(6, 'x');
const host = (site: string) => new URL(site).host;

const CSS = `
:root{--paper:#ebeae5;--panel:#f8f8f5;--ink:#111110;--sub:#6d6c66;--line:#d3d1c8;--dots:#c9c7bd;--key:#fff;--orange:#ff4f00;--blue:#2f5bea;--green:#12a150;--red:#e0352b;--yellow:#f5b800;--screen:#0d0d0c;--screen-ink:#efeee8;
--mono:ui-monospace,'SF Mono','JetBrains Mono','Roboto Mono',Menlo,Consolas,monospace;--sans:'Inter','Helvetica Neue',Helvetica,Arial,system-ui,sans-serif;--radius:16px;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#121211;--panel:#1b1b1a;--ink:#f0efe9;--sub:#9b9a92;--line:#2e2d2a;--dots:#262523;--key:#252523;--screen:#050505;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--paper) radial-gradient(var(--dots) 1px,transparent 1.2px) 0 0/18px 18px;color:var(--ink);font:16px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:68rem;margin:0 auto;padding:0 16px}
.bar{display:flex;align-items:center;gap:14px;padding:18px 0 6px}
.logo{font:800 22px/1 var(--mono);letter-spacing:-.04em}
.tag{font:500 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.12em;color:var(--sub);border:1px solid var(--line);border-radius:999px;padding:6px 10px;max-width:60vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.led{margin-left:auto;width:10px;height:10px;border-radius:50%;background:var(--sub);flex:none}
.led[data-state=ok]{background:var(--green);box-shadow:0 0 10px var(--green)}
.led[data-state=error]{background:var(--red);box-shadow:0 0 10px var(--red)}
.led[data-state=busy]{background:var(--orange);box-shadow:0 0 10px var(--orange);animation:blink 1s steps(2,start) infinite}
@keyframes blink{to{opacity:.35}}
.hero{padding:22px 0 18px}
.kicker{margin:0;font:600 12px/1 var(--mono);text-transform:uppercase;letter-spacing:.16em;color:var(--orange)}
h1{margin:12px 0 0;font-size:clamp(34px,7vw,58px);line-height:1;letter-spacing:-.045em;font-weight:800}
.lede{margin:14px 0 0;font-size:17px;max-width:40rem;color:var(--sub)}
.grid{display:grid;gap:14px;grid-template-columns:1fr}
@media (min-width:860px){.grid{grid-template-columns:1.15fr 1fr}.span{grid-column:1/-1}}
.col{display:flex;flex-direction:column;gap:14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px 18px 20px}
h2{display:flex;align-items:center;gap:10px;margin:0 0 14px;font:600 12px/1 var(--mono);text-transform:uppercase;letter-spacing:.14em;color:var(--sub)}
.num{font:700 11px/1 var(--mono);color:var(--paper);background:var(--ink);border-radius:6px;padding:4px 6px}
.field{padding:12px 0;border-top:1px solid var(--line)}
.field:first-of-type{border-top:0;padding-top:0}
.flabel{display:block;margin-bottom:10px;font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.1em;color:var(--sub)}
.hint{margin:8px 0 0;font-size:13px;color:var(--sub)}
.row{display:flex;flex-wrap:wrap;gap:8px}
.toggle{position:relative;cursor:pointer}
.toggle input{position:absolute;opacity:0;pointer-events:none}
.toggle span{display:inline-flex;align-items:center;gap:8px;font:600 12px/1 var(--mono);text-transform:uppercase;letter-spacing:.06em;border:1.5px solid var(--ink);border-radius:999px;padding:10px 13px;background:var(--key);transition:background .12s}
.toggle span::before{content:'';width:8px;height:8px;border-radius:50%;border:1.5px solid var(--ink);flex:none}
.toggle input:checked+span{background:var(--ink);color:var(--paper)}
.toggle input:checked+span::before{background:var(--orange);border-color:var(--orange)}
.toggle input:focus-visible+span,.key:focus-visible,input[type=text]:focus-visible,select:focus-visible{outline:2px solid var(--orange);outline-offset:3px}
input[type=text],select{width:100%;height:50px;font:500 15px/1.2 var(--mono);color:var(--ink);background:var(--key);border:1.5px solid var(--ink);border-radius:10px;padding:0 12px}
details{border:1.5px solid var(--ink);border-radius:12px;background:var(--key)}
summary{cursor:pointer;list-style:none;padding:12px 14px;font:600 12px/1.2 var(--mono);text-transform:uppercase;letter-spacing:.06em}
summary::-webkit-details-marker{display:none}
summary::after{content:'+';float:right}
details[open] summary::after{content:'−'}
.states{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;padding:4px 10px 12px;max-height:260px;overflow:auto}
.states .toggle span{width:100%;border-radius:8px;font-size:11px;padding:8px 9px;text-transform:none;letter-spacing:0}
.key{display:inline-flex;align-items:center;justify-content:center;gap:10px;min-height:52px;padding:0 22px;font:700 13px/1 var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--ink);background:var(--key);border:1.5px solid var(--ink);border-radius:12px;box-shadow:0 3px 0 var(--ink);cursor:pointer;text-decoration:none;transition:transform .06s,box-shadow .06s}
.key:active{transform:translateY(3px);box-shadow:0 0 0 var(--ink)}
.key--primary{background:var(--orange);border-color:#141414;color:#111;box-shadow:0 3px 0 #141414}
.key--wide{width:100%}
.actions{display:grid;gap:12px;margin-top:4px}
form.inline{display:contents}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px;padding:0;list-style:none}
.chip{display:inline-flex;align-items:center;gap:8px;font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.06em;border:1px solid var(--line);border-radius:999px;padding:8px 11px;background:var(--key)}
.chip::before,.dot{content:'';width:8px;height:8px;border-radius:50%;background:var(--sub);display:inline-block;flex:none}
[data-kind=age]::before,.dot[data-kind=age]{background:var(--orange)}
[data-kind=gender]::before,.dot[data-kind=gender]{background:var(--blue)}
[data-kind=pinCode]::before,.dot[data-kind=pinCode]{background:var(--green)}
[data-kind=state]::before,.dot[data-kind=state]{background:var(--yellow)}
.screen{position:relative;overflow:hidden;padding:20px 20px 22px;border-radius:var(--radius);background:var(--screen);color:var(--screen-ink);border:1px solid #000;min-height:160px}
.screen::after{content:'';position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.035) 0 1px,transparent 1px 3px)}
.screen .label{margin:0;font:600 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.14em;color:#8f8e86}
.screen .big{margin:10px 0 8px;font:800 clamp(34px,6vw,46px)/1 var(--mono);letter-spacing:-.03em;text-transform:uppercase}
.screen .big.ok{color:var(--green)}.screen .big.no{color:var(--orange)}.screen .big.idle{color:#55544f}
.screen p{margin:0;font:14px/1.6 var(--mono)}
.learned{margin:14px 0 0;padding:0;list-style:none;border-top:1px dashed #3a3935}
.learned li{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px dashed #3a3935;font:13px/1.4 var(--mono)}
.learned li span:first-child{color:#8f8e86;text-transform:uppercase;letter-spacing:.08em;font-size:11px}
.alert{margin:0 0 14px;padding:12px 14px;border:1.5px solid var(--red);border-radius:12px;background:color-mix(in srgb,var(--red) 8%,var(--panel));font-size:14px}
.note{margin:12px 0 0;font-size:13px;color:var(--sub)}
.sample{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));align-items:end}
.sample .key{grid-column:1/-1}
@media (min-width:860px){.sample{grid-template-columns:repeat(4,1fr) auto}.sample .key{grid-column:auto}}
.qrbox{display:flex;flex-direction:column;align-items:center;gap:14px;text-align:center}
.qrbox img{width:min(300px,80vw);height:auto;border-radius:12px;background:#fff;padding:8px;border:1.5px solid var(--ink)}
.mono{font-family:var(--mono);font-size:12px;overflow-wrap:anywhere}
.foot{padding:22px 0 28px;font:500 11px/1.6 var(--mono);text-transform:uppercase;letter-spacing:.1em;color:var(--sub)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

function layout(site: string, title: string, led: string, body: string, head = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)}</title><meta name="theme-color" content="#ebeae5">${head}<style>${CSS}</style></head>
<body><div class="wrap"><header class="bar"><span class="logo">zkID</span><span class="tag">Demo shop · ${escape(host(site))}</span><span class="led" data-state="${led}" aria-hidden="true"></span></header>
${body}
<footer class="foot">Verifier ${escape(site)} · a zkID demo, not a real shop</footer></div></body></html>`;
}

// The rules as chips.
export function ruleChips(rules: Rules) {
  const chips: [string, string][] = [];
  if (rules.age19) chips.push(['age', '19 or older']);
  if (rules.gender) chips.push(['gender', `Gender: ${rules.gender.map((g) => GENDERS[g]).join(' / ')}`]);
  if (rules.pinCode) chips.push(['pinCode', `PIN: ${rules.pinCode.map(pinShown).join(' / ')}`]);
  if (rules.state) chips.push(['state', `State: ${rules.state.join(' / ')}`]);
  if (!chips.length) chips.push(['none', 'Any UIDAI-signed QR']);
  return `<ul class="chips" data-testid="rules">${chips.map(([kind, text]) => `<li class="chip" data-kind="${kind}">${escape(text)}</li>`).join('')}</ul>`;
}

const toggle = (name: string, value: string, label: string, checked: boolean, type = 'checkbox') =>
  `<label class="toggle"><input type="${type}" name="${name}" value="${escape(value)}"${checked ? ' checked' : ''}><span>${escape(label)}</span></label>`;

function rulesForm(rules: Rules, error?: string) {
  const states = rules.state ?? [];
  const other = states.filter((s) => !STATES.some((known) => known.toLowerCase() === s.toLowerCase()));
  return `<section class="panel" aria-labelledby="rules-h"><h2 id="rules-h"><span class="num">01</span>Your rules for this shop</h2>
${error ? `<p class="alert" role="alert" data-testid="rules-error">${escape(error)}</p>` : ''}
<form method="post" action="/rules" data-testid="rules-form">
<div class="field"><span class="flabel">Age</span><div class="row">${toggle('age19', 'on', '19 or older', rules.age19)}</div></div>
<div class="field"><span class="flabel">Gender · none picked = any</span><div class="row">${Object.entries(GENDERS)
    .map(([g, label]) => toggle('gender', g, label, rules.gender?.includes(g as keyof typeof GENDERS) ?? false))
    .join('')}</div></div>
<div class="field"><label class="flabel" for="pin">PIN codes · empty = any</label>
<input type="text" id="pin" name="pin" inputmode="numeric" autocomplete="off" placeholder="560034, 5600xx, 110001" value="${escape((rules.pinCode ?? []).map(pinShown).join(', '))}">
<p class="hint">A full PIN code, or its first digits for a range (5600xx).</p></div>
<div class="field"><span class="flabel">States · none picked = any</span>
<details${states.length ? ' open' : ''}><summary>${states.length ? `${states.length} picked` : 'Pick states'}</summary><div class="states">${STATES.map((s) =>
    toggle('state', s, s, states.some((x) => x.toLowerCase() === s.toLowerCase())),
  ).join('')}${other.map((s) => toggle('state', s, s, true)).join('')}</div></details></div>
<button class="key key--wide" data-testid="save-rules">Save rules</button>
</form>
<p class="note">Your rules apply to your visit only. A rule on gender, PIN code or state shows this shop the value on your QR, not only that it passes: that is how the circuit works. Age shows only "19 or older".</p>
</section>`;
}

function learned(disclosed: Disclosed) {
  const rows: [string, string][] = [];
  if (disclosed.gender) rows.push(['Gender', GENDERS[disclosed.gender] ?? disclosed.gender]);
  if (disclosed.pinCode) rows.push(['PIN code', disclosed.pinCode]);
  if (disclosed.state) rows.push(['State', disclosed.state]);
  return rows.length
    ? `<ul class="learned" data-testid="learned">${rows.map(([k, v]) => `<li><span>${escape(k)}</span><span>${escape(v)}</span></li>`).join('')}</ul>`
    : '';
}

function result(session: Session) {
  const r = session.result;
  if (!r) {
    return `<section class="screen" data-testid="idle"><p class="label">03 · Display</p><p class="big idle">Ready</p><p>No proof yet. Set your rules, then verify.</p></section>`;
  }
  if (r.ok) {
    return `<section class="screen" data-testid="granted"><p class="label">03 · Proof checked</p><p class="big ok">Accepted</p>
<p>Access granted. Your account here is <strong>#${String(session.account).padStart(3, '0')}</strong>.</p>
<p>Code <span>${escape(r.nullifier.slice(0, 10))}…</span> · one per person here</p>${learned(r.disclosed)}</section>`;
  }
  return `<section class="screen" data-testid="refused"><p class="label">03 · Proof checked</p><p class="big no">Refused</p><p>${escape(r.code)}. ${escape(r.detail)}</p></section>`;
}

function sampleForm() {
  return `<section class="panel span" aria-labelledby="sample-h"><h2 id="sample-h"><span class="num">04</span>No Aadhaar at hand? Make a test QR</h2>
<form method="get" action="/sample-qr.png" class="sample" data-testid="sample-form">
<label><span class="flabel">Age</span><select name="age"><option value="adult">Adult</option><option value="minor">Under 19</option></select></label>
<label><span class="flabel">Gender</span><select name="gender">${Object.entries(GENDERS).map(([g, label]) => `<option value="${g}">${label}</option>`).join('')}</select></label>
<label><span class="flabel">PIN code</span><input type="text" name="pin" inputmode="numeric" value="560034" pattern="[1-9][0-9]{5}" required></label>
<label><span class="flabel">State</span><select name="state">${STATES.map((s) => `<option${s === 'Karnataka' ? ' selected' : ''}>${escape(s)}</option>`).join('')}</select></label>
<button class="key key--wide">Download test QR</button>
</form>
<p class="note">A synthetic QR (name "SYNTHETIC TEST PERSON") signed with this deployment's TEST key, not UIDAI's. Only this demo trusts it. Open it in zkID when the shop sends you there.</p>
</section>`;
}

export function shopPage(o: { site: string; session: Session; rules: Rules; testIssuerLabel?: string; samples: boolean; error?: string }) {
  const r = o.session.result;
  const led = !r ? 'idle' : r.ok ? 'ok' : 'error';
  const body = `<section class="hero"><p class="kicker">Demo shop · verifier</p><h1>Set the rules.<br>See only the proof.</h1>
<p class="lede">This shop checks your Aadhaar QR against your rules without ever seeing the QR. The proof is made on your device by the zkID app.</p></section>
<div class="grid">
${rulesForm(o.rules, o.error)}
<div class="col">
<section class="panel" aria-labelledby="verify-h"><h2 id="verify-h"><span class="num">02</span>Verify against</h2>
${ruleChips(o.rules)}
<div class="actions">
<form method="post" action="/start" class="inline"><button class="key key--primary key--wide" data-testid="verify">Verify with zkID</button></form>
<form method="post" action="/start?qr" class="inline"><button class="key key--wide" data-testid="verify-phone">Verify on my phone</button></form>
</div>
<p class="note">You need an image of the QR on an e-Aadhaar downloaded in the last 7 days. The age check runs on your device, on your own QR. This site receives a proof and a per-site code, plus the values your rules name, and keeps the code for 7 days.</p>
</section>
<div aria-live="polite">${result(o.session)}</div>
</div>
${o.samples ? sampleForm() : ''}
</div>
${o.testIssuerLabel ? `<p class="note">Demo: besides UIDAI, this shop trusts ${escape(o.testIssuerLabel)}.</p>` : ''}`;
  return layout(o.site, `Demo shop · ${host(o.site)}`, led, body);
}

// The request as a QR, for the holder app on another device. The page polls
// for the result, which arrives when that device posts the proof.
export function qrPage(site: string, rules: Rules, qr: string, url: string) {
  const body = `<section class="hero"><p class="kicker">Demo shop · verify on your phone</p><h1>Scan to prove.</h1></section>
<section class="panel qrbox" aria-labelledby="qr-h"><h2 id="qr-h"><span class="num">02</span>Request</h2>
${ruleChips(rules)}
<img data-testid="request-qr" src="${qr}" alt="QR code of the zkID request" width="300" height="300">
<p>Scan this with your phone's camera to open the request in zkID there.</p>
<p class="mono"><a href="${escape(url)}">${escape(url)}</a></p>
<p class="note" aria-live="polite">Waiting for the proof. The request expires in 15 minutes.</p>
</section>`;
  return layout(site, `Demo shop · ${host(site)}`, 'busy', body, `<script>setInterval(async () => { if (await (await fetch('/zkid/status')).json()) location = '/'; }, 2000);</script>`);
}
