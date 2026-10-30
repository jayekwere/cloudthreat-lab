import { readFileSync } from 'node:fs';
import { replay } from '../src/replay.js';
const file = process.argv[2];
if (!file) throw new Error('Usage: npx tsx scripts/replay.ts path/to/events.json');
const rules = JSON.parse(readFileSync('rules/detections.json', 'utf8'));
console.log(JSON.stringify(replay(JSON.parse(readFileSync(file, 'utf8')), rules), null, 2));
