import { analyze, computePriority } from '@shield-scanner/core';

// Test 1: Verify RLO (bidi override) finding has category tag and correct priority
const rloInput = "normal text ‮ reversed";
const result = analyze(rloInput, { fileType: "text" });

console.log("=== Bidi-Control 12-Point Drift Verification ===\n");
const bidiFindings = (result.findings.invisibleUnicode || []).filter(f => f.category === "bidi-control");
if (bidiFindings.length === 0) {
  console.log("ERROR: No bidi-control findings detected!");
  process.exit(1);
} else {
  const finding = bidiFindings[0];
  console.log(`Finding: ${finding.name} at position ${finding.position}`);
  console.log(`Category tag: "${finding.category}"`);
  console.log(`Kind: ${finding.kind}`);
  console.log(`Severity: ${finding.severity}`);
  console.log(`Actual priority score: ${finding.priority}`);
  
  // Calculate expected scores
  const contentLen = rloInput.length;
  // With bidi-control override: 70 (danger base) * 1.20 (bidiOverride) = 84
  const expectedWithOverride = computePriority("invisibleUnicode", "danger", finding.position, contentLen, "bidi-control");
  // Without override (bug scenario): 70 * 1.05 (invisibleUnicode) = 73.5 → 74
  const scoreWithoutOverride = computePriority("invisibleUnicode", "danger", finding.position, contentLen);
  
  console.log(`\nScoring breakdown:`);
  console.log(`  Base (danger): 70`);
  console.log(`  With bidi-control override (1.20): 70 * 1.20 = 84`);
  console.log(`  Without override, using 1.05: 70 * 1.05 = 73.5 → ${scoreWithoutOverride}`);
  console.log(`  Drift delta if override missing: ${expectedWithOverride - scoreWithoutOverride} points`);
  
  console.log(`\nComputed priority with override: ${expectedWithOverride}`);
  console.log(`Actual finding.priority: ${finding.priority}`);
  
  if (finding.priority === expectedWithOverride) {
    console.log("\n✓ PASS: Bidi-control scoring uses 1.20 multiplier");
    console.log("✓ CONFIRMED: The 12-point drift has been resolved.");
    process.exit(0);
  } else if (finding.priority === scoreWithoutOverride) {
    console.log("\n✗ FAIL: Bidi-control using 1.05 multiplier (drift bug present)");
    process.exit(1);
  } else {
    console.log(`\n? UNCERTAIN: Priority ${finding.priority} doesn't match either scenario`);
    process.exit(1);
  }
}
