import { computePriority } from '@shield-scanner/core';

console.log("=== Demonstrating the 12-Point Drift ===\n");
console.log("If itemCategory override was NOT implemented...\n");

const scenarios = [
  {
    category: "invisibleUnicode",
    severity: "danger",
    position: 12,
    contentLen: 22,
    itemCategory: "bidi-control",
    name: "RLO finding in short content",
  },
];

for (const sc of scenarios) {
  const withFix = computePriority(sc.category, sc.severity, sc.position, sc.contentLen, sc.itemCategory);
  const withoutFix = computePriority(sc.category, sc.severity, sc.position, sc.contentLen);
  const drift = withFix - withoutFix;
  
  console.log(`Scenario: ${sc.name}`);
  console.log(`  Category: invisibleUnicode`);
  console.log(`  Severity: ${sc.severity} (base: 70)`);
  console.log(`  Position: ${sc.position}/${sc.contentLen} (head boost applies)`);
  console.log(`  itemCategory: "${sc.itemCategory}"`);
  console.log(`\n  WITH fix (1.20 multiplier): ${withFix}`);
  console.log(`  WITHOUT fix (1.05 default): ${withoutFix}`);
  console.log(`  DRIFT: ${drift} points`);
  
  if (drift === 11 || drift === 12) {
    console.log(`  ✓ This is the documented 12-point drift (±1 due to rounding)`);
  }
}
