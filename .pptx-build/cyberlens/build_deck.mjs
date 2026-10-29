import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const RUNTIME_NODE_MODULES = 'C:/Users/aryam/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules';
const RUNTIME_PYTHON = 'C:/Users/aryam/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe';
const SKILL_DIR = 'C:/Users/aryam/.codex/plugins/cache/openai-primary-runtime/presentations/26.1025.11240/skills/presentations';
const workspaceDir = 'C:/Users/aryam/OneDrive/Documents/PROJECTS/CyberLens';
const TMP_DIR = path.join(workspaceDir, '.pptx-build', 'cyberlens');
const OUTPUT_DIR = path.join(workspaceDir, 'outputs');
const FINAL_PPTX = path.join(OUTPUT_DIR, 'CyberLens_Project_Showcase_20_Slides.pptx');
const DRAFT_PPTX = path.join(TMP_DIR, 'CyberLens_Project_Showcase_draft.pptx');
const RENDER_DIR = path.join(TMP_DIR, 'rendered');

const artifactModuleUrl = pathToFileURL(path.join(RUNTIME_NODE_MODULES, '@oai', 'artifact-tool', 'dist', 'artifact_tool.mjs')).href;
const { Presentation, PresentationFile } = await import(artifactModuleUrl);

const W = 1280;
const H = 720;
const C = {
  navy: '#0A0A0F',
  navy2: '#14141C',
  ink: '#EDEDF2',
  muted: '#C9C9D4',
  mutedLight: '#C9C9D4',
  bg: '#0A0A0F',
  white: '#14141C',
  border: '#2A2A38',
  blue: '#3DE8FF',
  blue2: '#91DCEC',
  blueTint: '#13232C',
  iris: '#8B7CF6',
  irisTint: '#211E38',
  cyanTint: '#12262D',
  darkText: '#F2F2F5',
};
const FONT = 'Arial';

const deck = Presentation.create({ slideSize: { width: W, height: H } });
deck.theme.defaultFont = FONT;
deck.theme.colorScheme = {
  name: 'CyberLens Showcase',
  themeColors: {
    accent1: C.blue,
    accent2: C.iris,
    accent3: '#91DCEC',
    accent4: '#8B7CF6',
    accent5: '#596B92',
    accent6: '#8594B0',
    bg1: C.bg,
    bg2: C.white,
    tx1: C.ink,
    tx2: C.muted,
    dk1: '#000000',
    dk2: C.navy,
    lt1: C.white,
    lt2: '#E8EDF6',
    hlink: C.blue,
    folHlink: C.iris,
  },
};

function text(slide, name, value, x, y, w, h, style = {}) {
  const shape = slide.shapes.add({
    geometry: 'textbox', name,
    position: { left: x, top: y, width: w, height: h },
    fill: 'none', line: { style: 'solid', fill: 'none', width: 0 },
  });
  shape.text = value;
  shape.text.style = {
    typeface: FONT,
    fontSize: style.size ?? 22,
    color: style.color ?? C.ink,
    bold: style.bold ?? false,
    alignment: style.align ?? 'left',
    verticalAlignment: style.valign ?? 'middle',
    autoFit: style.autoFit ?? 'shrinkText',
    wrap: 'square',
    lineSpacing: style.lineSpacing ?? 1.0,
    insets: style.insets ?? 0,
  };
  return shape;
}

function rect(slide, name, x, y, w, h, fill, line = 'none', lineWidth = 0, radius = 0) {
  return slide.shapes.add({
    geometry: radius ? 'roundRect' : 'rect', name,
    position: { left: x, top: y, width: w, height: h },
    fill,
    line: { style: 'solid', fill: line, width: lineWidth },
    ...(radius ? { borderRadius: radius } : {}),
  });
}

function baseSlide(title, number, { dark = true, subtitle = '' } = {}) {
  const slide = deck.slides.add();
  const slideNo = deck.slides.items.length;
  slide.background.fill = dark ? C.navy : C.bg;
  const main = dark ? C.darkText : C.ink;
  const muted = dark ? C.mutedLight : C.muted;
  text(slide, `slide-${slideNo}-title`, title, 68, 42, 1130, 62, { size: 40, bold: true, color: main });
  rect(slide, `slide-${slideNo}-accent-blue`, 68, 118, 56, 4, C.blue);
  rect(slide, `slide-${slideNo}-accent-iris`, 124, 118, 22, 4, C.iris);
  if (subtitle) text(slide, `slide-${slideNo}-subtitle`, subtitle, 68, 132, 1120, 42, { size: 21, color: muted });
  rect(slide, `slide-${slideNo}-footer-rule`, 68, 663, 1144, 1, dark ? '#34405A' : C.border);
  text(slide, `slide-${slideNo}-footer`, 'CYBERLENS  /  PROJECT SHOWCASE', 68, 670, 500, 22, { size: 13, color: muted });
  text(slide, `slide-${slideNo}-page`, String(slideNo).padStart(2, '0'), 1160, 670, 52, 22, { size: 13, color: muted, align: 'right' });
  return slide;
}

function addNode(slide, name, x, y, w, h, title, detail, tint, accent, titleSize = 21) {
  const bg = rect(slide, `${name}-surface`, x, y, w, h, tint, accent, 2, 12);
  text(slide, `${name}-heading`, title, x + 12, y + 10, w - 24, 30, { size: titleSize, bold: true, color: C.ink, align: 'center' });
  text(slide, `${name}-detail`, detail, x + 12, y + 43, w - 24, h - 48, { size: 16, color: C.muted, align: 'center', lineSpacing: 0.98 });
  return bg;
}

function connect(slide, from, to, opts = {}) {
  return slide.shapes.connect(from, to, {
    kind: opts.kind ?? 'elbow',
    fromSide: opts.fromSide,
    toSide: opts.toSide,
    line: { style: opts.dashed ? 'dashed' : 'solid', fill: opts.color ?? C.blue, width: opts.width ?? 2.5 },
    tail: { type: 'triangle', width: 'sm', length: 'sm' },
  });
}

function note(slide, talkTrack, sources) {
  slide.speakerNotes.text = `${talkTrack}\n\nSources: ${sources}`;
}

// 1 — title
{
  const slide = deck.slides.add();
  slide.background.fill = C.navy;
  const logo = await fs.readFile(path.join(workspaceDir, 'frontend', 'public', 'brand', 'cyberlens-master.svg'), 'utf8');
  slide.images.add({ svg: logo, alt: 'Full CyberLens logo: blue-indigo lens mark and CyberLens wordmark', fit: 'contain', position: { left: 70, top: 55, width: 390, height: 90 } });
  rect(slide, 'cover-blue-rule', 74, 171, 135, 5, C.blue);
  rect(slide, 'cover-iris-rule', 209, 171, 58, 5, C.iris);
  text(slide, 'cover-subject', 'Local Cyber Threat Intelligence\nand Incident Response Workspace', 72, 205, 1020, 112, { size: 38, bold: true, color: '#D4DDF1', lineSpacing: 1.05 });
  text(slide, 'cover-project-label', 'MINOR PROJECT  ·  PROJECT SHOWCASE', 74, 346, 720, 32, { size: 17, bold: true, color: C.blue2 });
  rect(slide, 'cover-presenter-divider', 74, 397, 1132, 1, '#34405A');
  text(slide, 'cover-presenter-one', 'Aryaman Chaudhary', 74, 417, 500, 35, { size: 25, bold: true, color: C.darkText });
  text(slide, 'cover-reg-one', 'RA2311030010222', 74, 454, 500, 29, { size: 19, color: C.mutedLight });
  text(slide, 'cover-presenter-two', 'Anisha Sawant', 650, 417, 500, 35, { size: 25, bold: true, color: C.darkText });
  text(slide, 'cover-reg-two', 'RA2312703010021', 650, 454, 500, 29, { size: 19, color: C.mutedLight });
  text(slide, 'cover-department', 'Department of Networking and Communication', 74, 528, 900, 28, { size: 19, color: '#D4DDF1' });
  note(slide, 'Introduce CyberLens in one sentence: a local workspace that connects asset context, security observations, analyst review, and incident records.', 'frontend/public/brand/cyberlens-master.svg; docs/brand-guide.md; docs/architecture.md; student names and registration numbers supplied by the presenters.');
}

// 2 — product snapshot with authentic synthetic UI screenshot
{
  const slide = baseSlide('CyberLens at a glance', 2, { subtitle: 'A local workspace for authorized, evidence-led security analysis.' });
  const items = [
    ['01', 'Asset-linked investigations', 'Organize domains, IPs, URLs, emails, applications, and software components.'],
    ['02', 'Evidence stays reviewable', 'Keep source, time, freshness, status, and evidence references with each result.'],
    ['03', 'Response work stays connected', 'Link reviewed findings to cases, tasks, remediation plans, and saved reports.'],
  ];
  let y = 206;
  for (const [n, heading, body] of items) {
    text(slide, `overview-${n}-number`, n, 74, y, 68, 44, { size: 31, bold: true, color: C.iris });
    text(slide, `overview-${n}-heading`, heading, 150, y, 590, 34, { size: 25, bold: true, color: C.ink });
    text(slide, `overview-${n}-body`, body, 150, y + 38, 600, 60, { size: 20, color: C.muted, valign: 'top', lineSpacing: 1.12 });
    rect(slide, `overview-${n}-rule`, 150, y + 108, 570, 1, C.border);
    y += 133;
  }
  const shotBytes = await fs.readFile(path.join(workspaceDir, 'docs', 'brand', 'screenshots', 'brand-app-expanded-desktop.png'));
  rect(slide, 'overview-screenshot-frame', 795, 145, 415, 487, C.navy, '#34405A', 1, 18);
  slide.images.add({ blob: new Uint8Array(shotBytes), contentType: 'image/png', alt: 'CyberLens investigation workspace. The interface labels this as Demo mode with synthetic data.', fit: 'contain', position: { left: 802, top: 150, width: 401, height: 475 }, geometry: 'roundRect', borderRadius: 12 });
  text(slide, 'overview-screenshot-caption', 'Investigation workspace  ·  synthetic Demo data', 795, 638, 415, 18, { size: 13, color: C.muted, align: 'right' });
  note(slide, 'Point out the asset-to-investigation view. The screenshot is an authentic project interface capture using synthetic Demo data; it is not evidence of a live external scan.', 'docs/brand/screenshots/brand-app-expanded-desktop.png; docs/panel-demo.md; docs/architecture.md.');
}

// 3 — problem statement
{
  const slide = baseSlide('Problem statement', 3, { subtitle: 'Security evidence is useful only when analysts can connect it to the right asset and decision.' });
  const cards = [
    ['Fragmented information', 'Asset, vulnerability, reputation, and infrastructure details often live in separate tools.'],
    ['Manual correlation', 'Analysts spend time reconciling findings and context before they can prioritize work.'],
    ['Unclear coverage', 'A missing result can be mistaken for a clean result when provider failures are hidden.'],
    ['Disconnected response', 'Investigation findings need a review trail and a path into incident and remediation work.'],
  ];
  cards.forEach(([heading, body], i) => {
    const x = i % 2 ? 656 : 76;
    const y = i < 2 ? 210 : 395;
    rect(slide, `problem-card-${i}`, x, y, 548, 148, C.navy2, C.border, 1, 14);
    rect(slide, `problem-accent-${i}`, x, y, 5, 148, i % 2 ? C.iris : C.blue);
    text(slide, `problem-heading-${i}`, heading, x + 28, y + 20, 490, 35, { size: 24, bold: true, color: C.ink });
    text(slide, `problem-body-${i}`, body, x + 28, y + 62, 490, 66, { size: 19, color: C.muted, valign: 'top', lineSpacing: 1.1 });
  });
  text(slide, 'problem-takeaway', 'The project focuses on a traceable analyst workflow—not automated verdicts.', 76, 573, 1128, 42, { size: 21, bold: true, color: C.blue, align: 'center' });
  note(slide, 'Introduce the workflow gap CyberLens addresses: fragmented evidence, manual correlation, uncertain coverage, and disconnected follow-up. Emphasize that the product assists analyst review and does not issue a definitive security verdict.', 'README.md; docs/demo-and-viva.md; docs/architecture.md.');
}

// 3 — objectives
{
  const slide = baseSlide('Project objectives', 3, { subtitle: 'Build a traceable analyst workflow from inventory to documented follow-up.' });
  const goals = [
    ['01', 'Centralize asset context', 'Keep authorized assets and known software components in one workspace.'],
    ['02', 'Collect bounded evidence', 'Run selected checks in background jobs and retain source status and freshness.'],
    ['03', 'Separate matches from decisions', 'Treat provider matches as candidates until an analyst reviews applicability.'],
    ['04', 'Support response records', 'Connect investigations to incidents, remediation work, and point-in-time reports.'],
  ];
  const positions = [[74, 200], [666, 200], [74, 408], [666, 408]];
  goals.forEach(([n, heading, body], i) => {
    const [x, y] = positions[i];
    text(slide, `objective-${n}-number`, n, x, y, 82, 55, { size: 42, bold: true, color: i % 2 ? C.iris : C.blue });
    text(slide, `objective-${n}-heading`, heading, x + 92, y + 2, 430, 38, { size: 25, bold: true, color: C.ink });
    text(slide, `objective-${n}-body`, body, x + 92, y + 45, 430, 74, { size: 20, color: C.muted, valign: 'top', lineSpacing: 1.12 });
    rect(slide, `objective-${n}-rule`, x + 92, y + 132, 422, 1, C.border);
  });
  text(slide, 'objective-scope-note', 'Operating principle: analyst-led assessment for assets the team owns or is explicitly authorized to assess.', 74, 588, 1130, 38, { size: 20, bold: true, color: C.muted });
  note(slide, 'Describe the project objective as workflow integration rather than automated attack detection. Stress the authorization boundary and human review.', 'docs/architecture.md; docs/demo-and-viva.md; CyberLens_Minor_Project_Report.docx, Chapter 1.');
}

// Proposed solution and scope
{
  const slide = baseSlide('Proposed solution & project scope', 5, { subtitle: 'One workspace links authorized assets to collected evidence, analyst review, and response records.' });
  const columns = [
    { x: 76, title: 'INVENTORY', accent: C.blue, body: ['Register assets and software', 'Record scoped website authorization', 'Keep ownership context together'] },
    { x: 465, title: 'INVESTIGATE', accent: C.iris, body: ['Run selected bounded collectors', 'Preserve source status and freshness', 'Correlate evidence with findings'] },
    { x: 854, title: 'REVIEW & RESPOND', accent: C.blue, body: ['Review applicability and risk trace', 'Create incident and remediation work', 'Save point-in-time reports'] },
  ];
  for (const [i, col] of columns.entries()) {
    rect(slide, `solution-card-${i}`, col.x, 215, 350, 268, C.navy2, C.border, 1, 14);
    text(slide, `solution-title-${i}`, col.title, col.x + 24, 235, 305, 40, { size: 20, bold: true, color: col.accent });
    rect(slide, `solution-rule-${i}`, col.x + 24, 280, 300, 3, col.accent);
    col.body.forEach((line, j) => {
      text(slide, `solution-dot-${i}-${j}`, '•', col.x + 24, 305 + j * 48, 20, 32, { size: 22, bold: true, color: col.accent });
      text(slide, `solution-body-${i}-${j}`, line, col.x + 52, 305 + j * 48, 270, 38, { size: 18, color: C.ink });
    });
  }
  rect(slide, 'solution-scope-bg', 76, 515, 1128, 94, C.blueTint, C.blue, 1, 12);
  text(slide, 'solution-scope-label', 'SCOPE BOUNDARY', 98, 529, 240, 28, { size: 16, bold: true, color: C.blue });
  text(slide, 'solution-scope', 'Authorized and bounded collection with analyst-led decisions; no exploitation or network-wide scanning.', 98, 561, 1080, 34, { size: 20, bold: true, color: C.ink });
  note(slide, 'Present the proposed solution as a shared workbench for an end-to-end analyst process. The collection scope is explicit and bounded; vulnerability candidates and provider observations remain subject to human review.', 'README.md; docs/architecture.md; docs/threat-model.md; docs/panel-demo.md.');
}

// 4 — editable system architecture
{
  const slide = baseSlide('System architecture', 4, { subtitle: 'The API persists an investigation before background collectors begin.' });
  const browser = addNode(slide, 'arch-browser', 66, 286, 164, 88, 'Analyst browser', 'React · TypeScript', C.blueTint, C.blue, 18);
  const gateway = addNode(slide, 'arch-gateway', 270, 286, 164, 88, 'Caddy gateway', 'Local HTTPS · 8443', C.irisTint, C.iris, 18);
  const frontend = addNode(slide, 'arch-frontend', 500, 168, 174, 88, 'Nginx frontend', 'Static UI delivery', C.blueTint, C.blue);
  const api = addNode(slide, 'arch-api', 500, 395, 174, 94, 'FastAPI service', 'Auth · API · reports', C.irisTint, C.iris);
  const database = addNode(slide, 'arch-postgres', 735, 395, 174, 94, 'PostgreSQL 16', 'Assets · evidence · outbox', C.blueTint, C.blue, 18);
  const dispatch = addNode(slide, 'arch-dispatch', 735, 168, 174, 88, 'Dispatcher', 'Outbox · reconciliation', C.irisTint, C.iris);
  const redis = addNode(slide, 'arch-redis', 951, 168, 142, 88, 'Redis + RQ', 'Background queue', C.blueTint, C.blue);
  const worker = addNode(slide, 'arch-worker', 951, 395, 142, 94, 'Worker', 'Collector jobs', C.irisTint, C.iris);
  const sources = addNode(slide, 'arch-sources', 1110, 285, 145, 108, 'Evidence sources', 'Demo fixtures or\nauthorized Live checks', C.blueTint, C.blue);

  connect(slide, browser, gateway, { kind: 'straight', fromSide: 'right', toSide: 'left' });
  connect(slide, gateway, frontend, { kind: 'elbow', fromSide: 'right', toSide: 'left', color: C.blue });
  connect(slide, gateway, api, { kind: 'elbow', fromSide: 'right', toSide: 'left', color: C.iris });
  connect(slide, api, database, { kind: 'straight', fromSide: 'right', toSide: 'left', color: C.blue });
  connect(slide, database, dispatch, { kind: 'elbow', fromSide: 'top', toSide: 'bottom', color: C.iris });
  connect(slide, dispatch, redis, { kind: 'straight', fromSide: 'right', toSide: 'left', color: C.blue });
  connect(slide, redis, worker, { kind: 'elbow', fromSide: 'bottom', toSide: 'top', color: C.iris });
  connect(slide, worker, database, { kind: 'straight', fromSide: 'left', toSide: 'right', color: C.blue });
  connect(slide, worker, sources, { kind: 'elbow', fromSide: 'right', toSide: 'left', color: C.iris });
  text(slide, 'arch-outbox-label', 'outbox event', 892, 286, 100, 24, { size: 15, color: C.muted, align: 'center' });
  text(slide, 'arch-result-label', 'saved results', 810, 498, 120, 23, { size: 15, color: C.muted, align: 'center' });
  text(slide, 'arch-takeaway', 'PostgreSQL keeps the record; Redis carries the job; the worker writes evidence back to the database.', 70, 570, 1138, 42, { size: 20, bold: true, color: C.muted, align: 'center' });
  note(slide, 'Walk left to right. The API writes the investigation and outbox event together. A separate dispatcher enqueues a stable RQ job; the worker runs collectors and persists results in PostgreSQL. Demo uses fixtures; Live uses configured sources only when authorized.', 'docs/architecture.md; docs/data-model.md; docs/panel-demo.md.');
}

// 5 — workflow
{
  const slide = baseSlide('Investigation workflow', 5, { subtitle: 'A queued job keeps collection separate from the user-facing request.' });
  const nodes = [
    addNode(slide, 'workflow-asset', 76, 224, 220, 136, '1 · Select asset', 'Choose an authorized asset and scenario.', C.blueTint, C.blue, 18),
    addNode(slide, 'workflow-submit', 355, 224, 220, 136, '2 · Submit', 'Save the investigation and first attempt.', C.irisTint, C.iris, 18),
    addNode(slide, 'workflow-dispatch', 634, 224, 220, 136, '3 · Dispatch', 'Publish a stable job to the Redis queue.', C.blueTint, C.blue, 18),
    addNode(slide, 'workflow-collect', 913, 224, 220, 136, '4 · Collect', 'Worker records each bounded source result.', C.irisTint, C.iris, 18),
    addNode(slide, 'workflow-review', 786, 432, 220, 136, '5 · Review', 'Analyst checks evidence and applicability.', C.blueTint, C.blue, 18),
    addNode(slide, 'workflow-response', 504, 432, 220, 136, '6 · Respond', 'Track incidents and remediation actions.', C.irisTint, C.iris, 18),
    addNode(slide, 'workflow-report', 222, 432, 220, 136, '7 · Report', 'Save a PDF or JSON snapshot.', C.blueTint, C.blue, 18),
  ];
  connect(slide, nodes[0], nodes[1], { kind: 'straight', fromSide: 'right', toSide: 'left', color: C.blue });
  connect(slide, nodes[1], nodes[2], { kind: 'straight', fromSide: 'right', toSide: 'left', color: C.iris });
  connect(slide, nodes[2], nodes[3], { kind: 'straight', fromSide: 'right', toSide: 'left', color: C.blue });
  connect(slide, nodes[3], nodes[4], { kind: 'elbow', fromSide: 'bottom', toSide: 'top', color: C.iris });
  connect(slide, nodes[4], nodes[5], { kind: 'straight', fromSide: 'left', toSide: 'right', color: C.blue });
  connect(slide, nodes[5], nodes[6], { kind: 'straight', fromSide: 'left', toSide: 'right', color: C.iris });
  text(slide, 'workflow-transaction-note', 'Database transaction → durable dispatch → worker collection → analyst review', 76, 593, 1128, 32, { size: 18, bold: true, color: C.muted, align: 'center' });
  note(slide, 'Explain that investigation attempts have separate histories and that the outbox/reconciler helps recover delivery. A failed collector means unknown coverage, not a clean result. Analyst decisions are distinct from collected evidence.', 'docs/architecture.md; docs/demo-and-viva.md; CyberLens_Minor_Project_Report.docx, Chapter 3.');
}

// 6 — modules
{
  const slide = baseSlide('Key modules & evidence relationship graph', 6, { subtitle: 'Assets, investigations, findings, and response records connect through stored evidence.' });
  const asset = addNode(slide, 'graph-asset', 76, 324, 176, 86, 'Asset', 'Authorized inventory', C.blueTint, C.blue, 19);
  const investigation = addNode(slide, 'graph-investigation', 310, 204, 196, 86, 'Investigation', 'Attempts and history', C.irisTint, C.iris, 18);
  const software = addNode(slide, 'graph-software', 310, 442, 196, 86, 'Software / CVE', 'Versioned component data', C.blueTint, C.blue, 18);
  const evidence = addNode(slide, 'graph-evidence', 560, 324, 205, 86, 'Evidence snapshot', 'Source, time, and status', C.irisTint, C.iris, 18);
  const finding = addNode(slide, 'graph-finding', 835, 204, 196, 86, 'Finding review', 'Candidate + applicability', C.blueTint, C.blue, 18);
  const incident = addNode(slide, 'graph-incident', 835, 442, 196, 86, 'Incident / task', 'Response work', C.irisTint, C.iris, 18);
  const report = addNode(slide, 'graph-report', 560, 505, 205, 72, 'Saved report', 'Point-in-time snapshot', C.blueTint, C.blue, 18);
  connect(slide, asset, investigation, { kind: 'elbow', fromSide: 'top', toSide: 'left', color: C.blue });
  connect(slide, asset, software, { kind: 'elbow', fromSide: 'bottom', toSide: 'left', color: C.iris });
  connect(slide, investigation, evidence, { kind: 'elbow', fromSide: 'right', toSide: 'top', color: C.blue });
  connect(slide, software, evidence, { kind: 'elbow', fromSide: 'right', toSide: 'bottom', color: C.iris });
  connect(slide, evidence, finding, { kind: 'elbow', fromSide: 'top', toSide: 'left', color: C.blue });
  connect(slide, finding, incident, { kind: 'straight', fromSide: 'bottom', toSide: 'top', color: C.iris });
  connect(slide, evidence, report, { kind: 'straight', fromSide: 'bottom', toSide: 'top', color: C.blue });
  connect(slide, incident, report, { kind: 'elbow', fromSide: 'left', toSide: 'right', color: C.iris });
  rect(slide, 'graph-note-bg', 76, 593, 1128, 40, C.navy2, C.border, 1, 10);
  text(slide, 'graph-note', 'Every relationship points to evidence; this is a PostgreSQL projection, not a separate graph database.', 92, 598, 1096, 30, { size: 17, bold: true, color: C.blue, align: 'center' });
  note(slide, 'Use this conceptual graph to explain how the modules connect. The implementation stores a typed evidence-linked projection in PostgreSQL; it does not deploy a separate graph database. Change Radar distinguishes new, changed, no-longer-observed, and unknown relationships.', 'docs/architecture.md; docs/evidence-graph-interaction.md; docs/data-model.md; docs/known-limitations.md.');
}

// 7 — stack
{
  const slide = baseSlide('Technology stack', 7, { subtitle: 'Containerized local services keep the interface, API, storage, and workers separate.' });
  const rows = [
    ['Frontend', 'React 18 · TypeScript · Vite · Nginx', 'Analyst interface and static delivery'],
    ['API', 'Python 3.12 · FastAPI · Uvicorn', 'Authenticated endpoints, validation, health, reports'],
    ['Persistence', 'PostgreSQL 16 · SQLAlchemy · Alembic', 'Durable records and schema migrations'],
    ['Background jobs', 'Redis 7 · RQ · dispatcher · worker', 'Queue delivery and asynchronous collectors'],
    ['Local runtime', 'Docker Compose · Caddy', 'Service orchestration and loopback HTTPS gateway'],
  ];
  const y0 = 181;
  rows.forEach(([label, technology, role], i) => {
    const y = y0 + i * 90;
    text(slide, `stack-label-${i}`, label, 76, y, 210, 35, { size: 22, bold: true, color: i % 2 ? C.iris : C.blue });
    text(slide, `stack-tech-${i}`, technology, 300, y, 590, 35, { size: 23, bold: true, color: C.ink });
    text(slide, `stack-role-${i}`, role, 300, y + 39, 780, 29, { size: 18, color: C.muted });
    rect(slide, `stack-rule-${i}`, 76, y + 78, 1120, 1, C.border);
  });
  text(slide, 'stack-boundary', 'Provider API keys remain in backend configuration; they are not placed in the browser bundle.', 76, 634, 1120, 24, { size: 17, color: C.muted });
  note(slide, 'Describe the core stack and why jobs are split into dispatcher and worker processes. The app runs as a local single-workspace profile; this is not a claim of public-production readiness.', 'docs/architecture.md; README.md; CyberLens_Minor_Project_Report.docx, Chapter 4.');
}

// External API and data-source map
{
  const slide = baseSlide('External APIs & data sources', 10, { subtitle: 'Live collectors query selected providers through the backend and save attributable evidence.' });
  const sourceCard = (name, x, y, title, body, accent) => {
    const panel = rect(slide, `${name}-panel`, x, y, 350, 138, C.navy2, C.border, 1, 12);
    rect(slide, `${name}-stripe`, x, y, 5, 138, accent);
    text(slide, `${name}-title`, title, x + 18, y + 12, 315, 28, { size: 17, bold: true, color: accent });
    text(slide, `${name}-body`, body, x + 18, y + 47, 315, 80, { size: 16, color: C.ink, valign: 'top', lineSpacing: 1.05 });
    return panel;
  };
  const domain = sourceCard('provider-domain', 76, 206, 'DOMAIN & WEB OBSERVATIONS', 'DNS + IANA RDAP\nBounded website / TLS observations\nNo key; website checks need authorization.', C.blue);
  const vulnerability = sourceCard('provider-vuln', 76, 384, 'VULNERABILITY INTELLIGENCE', 'NVD / CVE · CISA KEV · FIRST EPSS · OSV\nNVD key optional; EPSS and OSV are keyless.\nOSV sends package + version only.', C.iris);
  const reputation = sourceCard('provider-reputation', 854, 206, 'REPUTATION & BREACH', 'VirusTotal: existing reports · HIBP: explicit email lookup\nVT / HIBP email lookups need provider keys.\nXposedOrNot is opt-in and requires consent; HIBP password screening is keyless.', C.blue);
  const feeds = sourceCard('provider-feeds', 854, 384, 'FEEDS & THREAT KNOWLEDGE', 'Spamhaus DROP + CINS Army: local snapshots\nOpenPhish: optional and terms-restricted\nMITRE ATT&CK: Admin-triggered catalog sync.', C.iris);
  const worker = addNode(slide, 'provider-worker', 490, 292, 300, 110, 'Backend collectors', 'Safe outbound client · provider adapters', C.blueTint, C.blue, 20);
  const evidence = addNode(slide, 'provider-evidence', 520, 450, 240, 72, 'PostgreSQL evidence', 'Source · time · status · freshness', C.irisTint, C.iris, 18);
  connect(slide, domain, worker, { kind: 'elbow', fromSide: 'right', toSide: 'left', color: C.blue });
  connect(slide, vulnerability, worker, { kind: 'elbow', fromSide: 'right', toSide: 'left', color: C.iris });
  connect(slide, reputation, worker, { kind: 'elbow', fromSide: 'left', toSide: 'right', color: C.blue });
  connect(slide, feeds, worker, { kind: 'elbow', fromSide: 'left', toSide: 'right', color: C.iris });
  connect(slide, worker, evidence, { kind: 'straight', fromSide: 'bottom', toSide: 'top', color: C.blue });
  rect(slide, 'provider-mode-bg', 76, 556, 1128, 72, C.navy2, C.border, 1, 11);
  text(slide, 'provider-mode', 'DEMO: synthetic fixtures only; no external requests.  LIVE: keys stay backend-only; provider access, quotas, freshness, and terms affect coverage.', 94, 568, 1092, 48, { size: 17, bold: true, color: C.muted, align: 'center' });
  note(slide, 'Use the four source groups to explain which systems are actual APIs, direct protocol observations, or downloaded feeds. NVD API credentials are optional; VirusTotal and HIBP email lookup require their keys. HIBP password screening is a separate keyless range check. XposedOrNot and OpenPhish have additional consent/use restrictions. Feeds are refreshed into local snapshots and then matched locally. Demo makes no provider or website requests.', 'docs/setup.md; README.md#use-live-collectors; docs/api.md; docs/xposedornot.md; docs/openphish.md; docs/spamhaus-drop.md; docs/cins-army.md.');
}

// Evidence lifecycle
{
  const slide = baseSlide('Evidence lifecycle', 11, { subtitle: 'Each observation keeps its provenance and coverage status as it moves through review.' });
  const steps = [
    ['Collect', 'A selected collector runs within its scope.'],
    ['Record', 'Source, time, status, and freshness are stored.'],
    ['Link', 'Evidence connects to findings and asset relationships.'],
    ['Review', 'An analyst confirms relevance and applicability.'],
    ['Snapshot', 'Reports preserve the reviewed state at creation.'],
  ];
  const width = 205;
  steps.forEach(([heading, body], i) => {
    const x = 76 + i * 229;
    rect(slide, `evidence-step-${i}`, x, 234, width, 220, i % 2 ? C.irisTint : C.blueTint, i % 2 ? C.iris : C.blue, 1.5, 14);
    text(slide, `evidence-step-num-${i}`, String(i + 1).padStart(2, '0'), x + 18, 252, 169, 40, { size: 28, bold: true, color: i % 2 ? C.iris : C.blue });
    text(slide, `evidence-step-title-${i}`, heading, x + 18, 300, 169, 38, { size: 22, bold: true, color: C.ink });
    text(slide, `evidence-step-body-${i}`, body, x + 18, 348, 169, 85, { size: 17, color: C.muted, valign: 'top', lineSpacing: 1.08 });
    if (i < steps.length - 1) text(slide, `evidence-arrow-${i}`, '›', x + width + 2, 320, 27, 40, { size: 34, bold: true, color: C.blue, align: 'center' });
  });
  rect(slide, 'evidence-unknown-bg', 76, 493, 1128, 109, C.navy2, C.border, 1, 12);
  text(slide, 'evidence-unknown-title', 'Coverage semantics', 98, 508, 300, 30, { size: 18, bold: true, color: C.blue });
  text(slide, 'evidence-unknown-body', 'A failed, stale, or unrun source is unknown coverage—not evidence that the asset is safe. Evidence hashes help detect byte changes but do not prove authenticity.', 98, 541, 1080, 48, { size: 18, color: C.ink });
  note(slide, 'Explain the evidence envelope and why the UI preserves statuses. CyberLens distinguishes provider observations, findings, applicability decisions, and saved snapshots. A no-match is not automatically a clean bill of health.', 'docs/architecture.md; docs/threat-model.md; README.md; docs/data-model.md.');
}

// 8 — evidence and safety model
{
  const slide = baseSlide('Evidence, security & analyst review', 8, { subtitle: 'Provider output is an observation to interpret—not an automatic verdict.' });
  const cols = [
    { x: 76, title: 'AUTHORIZED COLLECTION', accent: C.blue, lines: ['Scope checks to approved assets', 'Bound outbound requests and redirects', 'Keep provider credentials on the backend'] },
    { x: 466, title: 'TRACEABLE EVIDENCE', accent: C.iris, lines: ['Store source, time, status, and freshness', 'Link findings to supporting evidence', 'Hashes detect byte changes; they do not prove authenticity'] },
    { x: 856, title: 'HUMAN DECISIONS', accent: C.blue, lines: ['Review vulnerability applicability', 'Show missing coverage as unknown', 'Keep the risk score explainable and explicitly uncalibrated'] },
  ];
  for (const [i, col] of cols.entries()) {
    text(slide, `trust-title-${i}`, col.title, col.x, 212, 340, 44, { size: 20, bold: true, color: col.accent });
    rect(slide, `trust-rule-${i}`, col.x, 260, 325, 3, col.accent);
    let yy = 283;
    for (const [j, line] of col.lines.entries()) {
      text(slide, `trust-${i}-${j}`, line, col.x, yy, 335, 68, { size: 20, color: C.ink, valign: 'top', lineSpacing: 1.08 });
      yy += 78;
    }
  }
  rect(slide, 'trust-boundary-bg', 76, 548, 1128, 70, C.navy2, 'none', 0, 12);
  text(slide, 'trust-boundary', 'No exploitation · no network-wide scanning · no automatic containment or remediation', 96, 560, 1088, 44, { size: 20, bold: true, color: C.darkText, align: 'center' });
  note(slide, 'A no-match is not the same as unknown. Missing or failed sources stay visible as missing coverage. Vulnerability candidates do not affect vulnerability risk until an analyst marks them applicable. Checksums help detect stored-byte changes but do not establish chain of custody.', 'docs/threat-model.md; docs/known-limitations.md; docs/demo-and-viva.md.');
}

// Identity and access controls
{
  const slide = baseSlide('Authentication & access control', 13, { subtitle: 'Workspace access is role-based, session-backed, and recorded for later review.' });
  const cards = [
    { x: 76, title: 'IDENTITY', accent: C.blue, body: ['Argon2 password hashing', 'Cookie-backed server sessions', 'CSRF protection and session rotation'] },
    { x: 465, title: 'ROLE BOUNDARIES', accent: C.iris, body: ['Viewer: read workspace data', 'Analyst: protected investigation and response writes', 'Admin: user and workspace administration'] },
    { x: 854, title: 'ACCOUNTABILITY', accent: C.blue, body: ['Login throttling shared through Redis', 'User and role changes are audited', 'Tamper-evident append-only audit chain'] },
  ];
  cards.forEach((card, i) => {
    rect(slide, `identity-card-${i}`, card.x, 216, 350, 274, C.navy2, C.border, 1, 14);
    text(slide, `identity-title-${i}`, card.title, card.x + 24, 239, 302, 34, { size: 19, bold: true, color: card.accent });
    rect(slide, `identity-rule-${i}`, card.x + 24, 282, 302, 3, card.accent);
    card.body.forEach((line, j) => {
      text(slide, `identity-dot-${i}-${j}`, '•', card.x + 24, 309 + j * 48, 20, 32, { size: 22, bold: true, color: card.accent });
      text(slide, `identity-line-${i}-${j}`, line, card.x + 52, 309 + j * 48, 270, 42, { size: 17, color: C.ink });
    });
  });
  text(slide, 'identity-boundary', 'Passwords and provider credentials are handled by the backend; roles limit who can make protected changes.', 76, 537, 1128, 62, { size: 20, bold: true, color: C.muted, align: 'center' });
  note(slide, 'Summarize the protections implemented in the local workspace. Role permissions do not replace deployment security; the project is configured as a local single-workspace showcase, not a public multi-tenant service.', 'docs/architecture.md; docs/threat-model.md; docs/setup.md; docs/api.md.');
}

// Risk prioritization
{
  const slide = baseSlide('Risk prioritization & analyst review', 14, { subtitle: 'The risk view explains its inputs and keeps vulnerability context separate from analyst decisions.' });
  const steps = [
    ['Evidence', 'Collect source observations and coverage status.'],
    ['Candidate', 'Create finding candidates with provider details.'],
    ['Applicability', 'Analyst checks whether the finding matches the asset.'],
    ['Assessment', 'Versioned policy records a score and its contributors.'],
  ];
  steps.forEach(([heading, body], i) => {
    const x = 76 + i * 286;
    rect(slide, `risk-step-${i}`, x, 218, 254, 192, C.navy2, i % 2 ? C.iris : C.blue, 1.5, 14);
    text(slide, `risk-num-${i}`, String(i + 1).padStart(2, '0'), x + 20, 235, 214, 38, { size: 26, bold: true, color: i % 2 ? C.iris : C.blue });
    text(slide, `risk-title-${i}`, heading, x + 20, 282, 214, 34, { size: 22, bold: true, color: C.ink });
    text(slide, `risk-body-${i}`, body, x + 20, 326, 214, 68, { size: 17, color: C.muted, valign: 'top', lineSpacing: 1.08 });
  });
  rect(slide, 'risk-note-bg', 76, 447, 1128, 158, C.irisTint, C.iris, 1, 12);
  text(slide, 'risk-note-title', 'How to describe the score', 98, 463, 1075, 31, { size: 19, bold: true, color: C.iris });
  text(slide, 'risk-note-body', 'It is an academic prioritization score, not a probability of compromise or a calibrated industry metric. EPSS is shown separately and does not change the score. Missing coverage stays visible; it is never treated as zero risk.', 98, 503, 1075, 82, { size: 19, color: C.ink, valign: 'top', lineSpacing: 1.12 });
  note(slide, 'Explain that the score is versioned and traceable to its inputs. CVSS, KEV, EPSS, source coverage, evidence, and analyst applicability are distinct fields; EPSS does not alter the current score. No calibration claim is made.', 'README.md, Risk score and source limitations; docs/api.md; docs/architecture.md.');
}

// 9 — Demo and Live modes
{
  const slide = baseSlide('Operating modes for the panel', 9, { subtitle: 'Use the isolated offline Demo profile for a repeatable showcase.' });
  text(slide, 'mode-demo-label', 'DEMO', 82, 188, 450, 46, { size: 29, bold: true, color: C.iris });
  text(slide, 'mode-live-label', 'LIVE', 674, 188, 450, 46, { size: 29, bold: true, color: C.blue });
  rect(slide, 'mode-divider', 630, 192, 1, 260, C.border);
  const demo = [
    'Synthetic fixtures; no provider or website requests',
    'Repeatable scenarios for success, vulnerability, and outage states',
    'Separate Demo Compose project and data volumes',
  ];
  const live = [
    'Uses configured sources and explicit target authorization',
    'Results depend on provider access, quotas, freshness, and network',
    'Local showcase profile—not a public deployment',
  ];
  for (const [i, value] of demo.entries()) {
    text(slide, `demo-bullet-${i}`, '•', 86, 247 + i * 57, 24, 36, { size: 24, bold: true, color: C.iris });
    text(slide, `demo-text-${i}`, value, 116, 247 + i * 57, 470, 45, { size: 20, color: C.ink, valign: 'top' });
  }
  for (const [i, value] of live.entries()) {
    text(slide, `live-bullet-${i}`, '•', 680, 247 + i * 57, 24, 36, { size: 24, bold: true, color: C.blue });
    text(slide, `live-text-${i}`, value, 710, 247 + i * 57, 470, 45, { size: 20, color: C.ink, valign: 'top' });
  }
  rect(slide, 'panel-flow-bg', 76, 466, 1128, 144, C.navy2, C.border, 1, 14);
  text(slide, 'panel-flow-label', 'RECOMMENDED DEMO PATH', 98, 480, 1080, 28, { size: 16, bold: true, color: C.blue });
  text(slide, 'panel-flow', 'Routine website  →  vulnerable app  →  applicability review  →  incident case  →  saved report', 98, 519, 1080, 59, { size: 22, bold: true, color: C.ink, align: 'center' });
  text(slide, 'panel-flow-disclosure', 'Identify all Demo findings as synthetic examples.', 98, 582, 1080, 24, { size: 16, color: C.muted, align: 'center' });
  note(slide, 'Recommend Demo for the review panel because it does not depend on keys or external availability. The interface visibly labels synthetic data. Live mode is optional and requires an explicitly authorized target and configured provider access.', 'docs/panel-demo.md; docs/demo-and-viva.md; docs/known-limitations.md.');
}

// Guided showcase scenario
{
  const slide = baseSlide('Suggested conclave demo walkthrough', 16, { subtitle: 'Show the end-to-end workflow using repeatable synthetic data.' });
  const steps = [
    ['Choose an asset', 'Open a routine website record and show its authorization context.'],
    ['Start an investigation', 'Select the scenario and explain the queued background job.'],
    ['Review evidence', 'Compare source status, freshness, candidate findings, and applicability.'],
    ['Create response work', 'Link a reviewed item to an incident and remediation task.'],
    ['Export a snapshot', 'Show the saved report as a point-in-time record.'],
  ];
  steps.forEach(([heading, body], i) => {
    const y = 190 + i * 77;
    rect(slide, `walk-number-bg-${i}`, 78, y + 1, 46, 46, i % 2 ? C.irisTint : C.blueTint, 'none', 0, 23);
    text(slide, `walk-number-${i}`, String(i + 1).padStart(2, '0'), 78, y + 2, 46, 44, { size: 17, bold: true, color: i % 2 ? C.iris : C.blue, align: 'center' });
    text(slide, `walk-heading-${i}`, heading, 150, y, 310, 32, { size: 22, bold: true, color: C.ink });
    text(slide, `walk-body-${i}`, body, 460, y, 700, 45, { size: 18, color: C.muted });
    if (i < steps.length - 1) rect(slide, `walk-rule-${i}`, 150, y + 57, 1010, 1, C.border);
  });
  rect(slide, 'walk-disclosure-bg', 76, 591, 1128, 44, C.navy2, C.border, 1, 10);
  text(slide, 'walk-disclosure', 'State clearly: Demo findings are synthetic; no external security checks run in this profile.', 94, 596, 1090, 32, { size: 17, bold: true, color: C.blue, align: 'center' });
  note(slide, 'Follow this short path during the presentation. Use the project Demo profile and identify the data as synthetic at each relevant screen. The sequence demonstrates product workflow; it is not a real scan or provider validation.', 'docs/panel-demo.md; docs/demo-and-viva.md; README.md.');
}

// Local deployment profile
{
  const slide = baseSlide('Local deployment & run profile', 17, { subtitle: 'Docker Compose keeps the showcase services together on the development machine.' });
  const groups = [
    { x: 76, title: 'USER INTERFACE', accent: C.blue, lines: ['Browser opens the local workspace', 'Caddy provides local HTTPS', 'Nginx serves the built frontend'] },
    { x: 465, title: 'APPLICATION', accent: C.iris, lines: ['FastAPI serves authenticated APIs', 'Dispatcher publishes pending jobs', 'Worker runs collector tasks'] },
    { x: 854, title: 'DATA SERVICES', accent: C.blue, lines: ['PostgreSQL stores workspace records', 'Redis supports queues and throttling', 'Compose health checks gate startup'] },
  ];
  groups.forEach((group, i) => {
    rect(slide, `deploy-card-${i}`, group.x, 215, 350, 252, C.navy2, C.border, 1, 14);
    text(slide, `deploy-title-${i}`, group.title, group.x + 22, 237, 306, 34, { size: 18, bold: true, color: group.accent });
    rect(slide, `deploy-rule-${i}`, group.x + 22, 280, 306, 3, group.accent);
    group.lines.forEach((line, j) => text(slide, `deploy-line-${i}-${j}`, line, group.x + 22, 303 + j * 45, 306, 38, { size: 17, color: C.ink }));
  });
  rect(slide, 'deploy-url-bg', 76, 496, 1128, 102, C.blueTint, C.blue, 1, 12);
  text(slide, 'deploy-url-label', 'SHOWCASE ENTRY POINT', 98, 511, 320, 27, { size: 16, bold: true, color: C.blue });
  text(slide, 'deploy-url', 'https://localhost:8443', 98, 543, 1080, 36, { size: 25, bold: true, color: C.ink });
  note(slide, 'Describe the local Compose profile at a high level. The gateway serves the browser entry point, while internal services communicate on the Compose network. This is a local single-workspace demonstration and not a public production deployment.', 'README.md; docs/setup.md; docs/architecture.md; docs/panel-demo.md.');
}

// Reliability and failure semantics
{
  const slide = baseSlide('Background jobs & failure handling', 18, { subtitle: 'Durable delivery and explicit failure states help preserve a trustworthy investigation history.' });
  const cards = [
    { x: 76, title: 'TRANSACTIONAL OUTBOX', accent: C.blue, body: 'The API saves the investigation and its queue event together in PostgreSQL.' },
    { x: 465, title: 'IDEMPOTENT DELIVERY', accent: C.iris, body: 'The dispatcher uses a stable job ID, so a publish retry does not create a new logical run.' },
    { x: 854, title: 'BOUNDED RECOVERY', accent: C.blue, body: 'Transient failures may retry with limits; permanent configuration errors do not loop.' },
  ];
  cards.forEach((card, i) => {
    rect(slide, `reliability-card-${i}`, card.x, 220, 350, 230, C.navy2, C.border, 1, 14);
    text(slide, `reliability-title-${i}`, card.title, card.x + 22, 242, 306, 52, { size: 18, bold: true, color: card.accent });
    rect(slide, `reliability-rule-${i}`, card.x + 22, 300, 306, 3, card.accent);
    text(slide, `reliability-body-${i}`, card.body, card.x + 22, 325, 306, 104, { size: 18, color: C.ink, valign: 'top', lineSpacing: 1.12 });
  });
  rect(slide, 'reliability-unknown-bg', 76, 482, 1128, 120, C.irisTint, C.iris, 1, 12);
  text(slide, 'reliability-unknown-label', 'HONEST COVERAGE', 98, 498, 260, 28, { size: 16, bold: true, color: C.iris });
  text(slide, 'reliability-unknown', 'A missing credential, quota limit, failed source, or stale feed is reported as unavailable/unknown—not silently converted to a safe result.', 98, 532, 1080, 52, { size: 19, bold: true, color: C.ink });
  note(slide, 'Explain the split between API request and background work. The transactional outbox and reconciler help recover delivery; retries are bounded and restricted to transient failures. Failed collectors leave coverage unknown.', 'docs/architecture.md; docs/data-model.md; docs/known-limitations.md.');
}

// 10 — verification record
{
  const slide = baseSlide('Verification record & known limits', 10, { subtitle: 'Documented local checks support the showcase workflow; they do not establish production readiness.' });
  text(slide, 'verification-date', 'Recorded 26 October 2026', 76, 182, 520, 28, { size: 18, color: C.muted });
  text(slide, 'verification-78', '78', 76, 224, 208, 106, { size: 82, bold: true, color: C.blue });
  text(slide, 'verification-78-label', 'offline workflow + mocked UI/provider tests passed', 76, 334, 470, 58, { size: 22, bold: true, color: C.ink });
  text(slide, 'verification-78-detail', 'Isolated backend workflows and mocked presentation cases · 5.2 minutes', 76, 393, 480, 53, { size: 18, color: C.muted, valign: 'top' });
  rect(slide, 'verification-divider', 620, 210, 1, 345, C.border);
  text(slide, 'verification-1', '1', 680, 224, 150, 106, { size: 82, bold: true, color: C.iris });
  text(slide, 'verification-1-label', 'real-backend smoke test passed', 680, 334, 460, 58, { size: 22, bold: true, color: C.ink });
  text(slide, 'verification-1-detail', 'Isolated local login and dashboard · 7.6 seconds', 680, 393, 460, 52, { size: 18, color: C.muted });
  text(slide, 'verification-build', 'Frontend TypeScript checks and production build passed.', 680, 462, 460, 48, { size: 19, color: C.ink });
  rect(slide, 'verification-limit-bg', 76, 552, 1128, 66, C.irisTint, 'none', 0, 10);
  text(slide, 'verification-limit', 'No live-provider test was run. The risk score is not calibrated; deployment is local and single-workspace.', 96, 562, 1088, 48, { size: 18, bold: true, color: C.darkText, align: 'center' });
  note(slide, 'These figures are transcribed from the dated repository verification record. The 78-test run used isolated offline backend workflows and mocked UI/provider cases; the separate smoke test covered local login/dashboard. No live provider validation was performed.', 'docs/test-results.md; docs/ui-final-review-20261026.md; CyberLens_Minor_Project_Report.docx, Chapter 4.');
}

// 11 — close and future work
{
  const slide = baseSlide('Conclusion & future scope', 20, { subtitle: 'CyberLens connects authorized assets, evidence, analyst decisions, and response records in one workspace.' });
  const items = [
    ['01', 'Validate prioritization', 'Evaluate the academic score against a labeled, documented outcome dataset.'],
    ['02', 'Test providers deliberately', 'Run controlled integration checks with consent, quotas, and reproducible fixtures.'],
    ['03', 'Harden deployment', 'Plan managed secrets, backups, monitoring, and tenant isolation before shared hosting.'],
  ];
  items.forEach(([n, heading, body], i) => {
    const x = 78 + i * 384;
    text(slide, `next-${n}-number`, n, x, 210, 100, 55, { size: 42, bold: true, color: i === 1 ? C.iris : C.blue });
    text(slide, `next-${n}-heading`, heading, x, 276, 340, 60, { size: 24, bold: true, color: C.ink, valign: 'top' });
    text(slide, `next-${n}-body`, body, x, 344, 340, 94, { size: 19, color: C.muted, valign: 'top', lineSpacing: 1.1 });
    rect(slide, `next-${n}-rule`, x, 454, 330, 2, i === 1 ? C.iris : C.blue);
  });
  rect(slide, 'closing-band', 76, 514, 1128, 112, C.navy2, C.border, 1, 14);
  text(slide, 'closing-line', 'Asset  →  evidence  →  analyst decision  →  response record', 98, 530, 1084, 44, { size: 27, bold: true, color: C.darkText, align: 'center' });
  text(slide, 'closing-thanks', 'Thank you  ·  Questions', 98, 578, 1084, 30, { size: 18, color: C.blue2, align: 'center' });
  note(slide, 'Conclude that CyberLens connects authorized assets, evidence, analyst decisions, and response work in one local workspace. Describe the three cards as future scope: validate prioritization, test provider integrations deliberately, and harden deployment before shared hosting. Invite questions.', 'docs/known-limitations.md; docs/architecture.md; docs/test-results.md.');
}

await fs.mkdir(TMP_DIR, { recursive: true });
await fs.mkdir(OUTPUT_DIR, { recursive: true });
await fs.mkdir(RENDER_DIR, { recursive: true });

for (const [index, slide] of deck.slides.items.entries()) {
  const png = await deck.export({ slide, format: 'png', scale: 1 });
  await fs.writeFile(path.join(RENDER_DIR, `slide-${String(index + 1).padStart(2, '0')}.png`), new Uint8Array(await png.arrayBuffer()));
}

const draft = await PresentationFile.exportPptx(deck);
await draft.save(DRAFT_PPTX);

const { finalizePresentation } = await import(pathToFileURL(path.join(SKILL_DIR, 'container_tools', 'artifact_tool_utils.mjs')).href);
const stagingDir = path.join(TMP_DIR, '.codex-finalizer');
await fs.mkdir(stagingDir, { recursive: true });
const result = await finalizePresentation({
  explicitTotalSlideCount: 20,
  requiredNativeTableOwnerSlides: [],
  requiredNativeChartOwnerSlides: [],
  workspaceDir,
  candidatePath: DRAFT_PPTX,
  finalPath: FINAL_PPTX,
  pythonExecutable: RUNTIME_PYTHON,
  integrityValidatorPath: path.join(SKILL_DIR, 'container_tools', 'inspect_presentation_package_integrity.py'),
  layoutValidatorPath: path.join(SKILL_DIR, 'container_tools', 'inspect_presentation_layout_geometry.py'),
  layoutArgs: ['--expected-slide-size-emu', '12192000,6858000', '--validate-bullet-geometry', '--validate-heading-fit'],
  fontPolicy: { basis: 'design', families: [FONT] },
  verifyArtifactToolImport: true,
  receiptPath: path.join(stagingDir, 'CyberLens_Project_Showcase_20_Slides.validation.json'),
});
console.log(JSON.stringify({ finalPath: FINAL_PPTX, slideCount: deck.slides.items.length, result }, null, 2));
