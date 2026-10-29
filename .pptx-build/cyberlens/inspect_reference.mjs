import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const modules = 'C:/Users/aryam/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules';
const { FileBlob, PresentationFile } = await import(pathToFileURL(path.join(modules, '@oai', 'artifact-tool', 'dist', 'artifact_tool.mjs')).href);
const input = 'C:/Users/aryam/Downloads/CyberLens (1).pptx';
const out = 'C:/Users/aryam/OneDrive/Documents/PROJECTS/CyberLens/.pptx-build/cyberlens/reference-rendered';
await fs.mkdir(out, { recursive: true });
const p = await PresentationFile.importPptx(await FileBlob.load(input));
console.log('slides', p.slides.items.length, 'size', JSON.stringify(p.toProto().slideSize ?? p.toProto().slide_size ?? null));
console.log((await p.inspect({ kind: 'slide,textbox,shape,image,table,chart,layout', maxChars: 60000 })).ndjson);
for (const [i, slide] of p.slides.items.entries()) {
  const png = await p.export({ slide, format: 'png', scale: 1 });
  await fs.writeFile(path.join(out, `slide-${String(i + 1).padStart(2, '0')}.png`), new Uint8Array(await png.arrayBuffer()));
}
