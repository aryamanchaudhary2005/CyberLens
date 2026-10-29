import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const runtime = 'C:/Users/aryam/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules';
const { FileBlob, PresentationFile } = await import(pathToFileURL(path.join(runtime, '@oai', 'artifact-tool', 'dist', 'artifact_tool.mjs')).href);
const root = 'C:/Users/aryam/OneDrive/Documents/PROJECTS/CyberLens';
const file = path.join(root, 'outputs', 'CyberLens_Project_Showcase_20_Slides.pptx');
const out = path.join(root, '.pptx-build', 'cyberlens', 'final-rendered-20-slides');
await fs.mkdir(out, { recursive: true });
const presentation = await PresentationFile.importPptx(await FileBlob.load(file));
for (const [i, slide] of presentation.slides.items.entries()) {
  const png = await presentation.export({ slide, format: 'png', scale: 1 });
  await fs.writeFile(path.join(out, `slide-${String(i + 1).padStart(2, '0')}.png`), new Uint8Array(await png.arrayBuffer()));
}
console.log(JSON.stringify({ slideCount: presentation.slides.items.length, rendered: presentation.slides.items.length, directory: out }));
