import { computePriority } from '@shield-scanner/core';

const contentLen = "normal text ‮ reversed".length; // 22 chars
const position = 12; // RLO position

// Computing prominence boost
const head = Math.max(0, 1 - position / contentLen);
const prominence = 1 + 0.15 * head;

console.log(`Content length: ${contentLen}`);
console.log(`Finding position: ${position}`);
console.log(`Head calculation: 1 - ${position}/${contentLen} = ${head.toFixed(4)}`);
console.log(`Prominence: 1 + 0.15 * ${head.toFixed(4)} = ${prominence.toFixed(4)}`);

// With bidi-control (1.20)
const scoreWithBidi = 70 * 1.20 * prominence;
console.log(`\nWith bidi-control (1.20):`);
console.log(`  70 * 1.20 * ${prominence.toFixed(4)} = ${scoreWithBidi.toFixed(2)} → ${Math.round(scoreWithBidi)}`);

// Without override (1.05)
const scoreWithoutBidi = 70 * 1.05 * prominence;
console.log(`\nWithout bidi-control (1.05):`);
console.log(`  70 * 1.05 * ${prominence.toFixed(4)} = ${scoreWithoutBidi.toFixed(2)} → ${Math.round(scoreWithoutBidi)}`);

const delta = Math.round(scoreWithBidi) - Math.round(scoreWithoutBidi);
console.log(`\nDrift delta: ${delta} points`);

// Verify with computePriority
const withBidi = computePriority("invisibleUnicode", "danger", position, contentLen, "bidi-control");
const withoutBidi = computePriority("invisibleUnicode", "danger", position, contentLen);
console.log(`\ncomputePriority verification:`);
console.log(`  With bidi-control tag: ${withBidi}`);
console.log(`  Without tag: ${withoutBidi}`);
console.log(`  Actual delta: ${withBidi - withoutBidi} points`);
