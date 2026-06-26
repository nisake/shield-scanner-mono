import { analyze, computePriority } from '@shield-scanner/core';

console.log("=== Comprehensive Bidi-Control 12-Point Drift Verification ===\n");

const testCases = [
  {
    name: "RLO (Right-to-Left Override)",
    input: "normal text ‮ reversed",
    expectedKind: "override",
  },
  {
    name: "LRE (Left-to-Right Embedding)",
    input: "Hello ‪World‬",
    expectedKind: "embedding",
  },
  {
    name: "FSI (First Strong Isolate)",
    input: "Text ⁦isolated⁩ more",
    expectedKind: "isolate",
  },
];

let passCount = 0;
let failCount = 0;

for (const testCase of testCases) {
  console.log(`\nTest: ${testCase.name}`);
  console.log(`Input: "${testCase.input}"`);
  
  const result = analyze(testCase.input, { fileType: "text" });
  const bidiFindings = (result.findings.invisibleUnicode || []).filter(f => f.category === "bidi-control");
  
  if (bidiFindings.length === 0) {
    console.log("  ✗ FAIL: No bidi-control findings detected");
    failCount++;
    continue;
  }
  
  const finding = bidiFindings[0];
  const contentLen = testCase.input.length;
  
  // Compute what the score SHOULD be
  const correctScore = computePriority("invisibleUnicode", "danger", finding.position, contentLen, "bidi-control");
  const driftedScore = computePriority("invisibleUnicode", "danger", finding.position, contentLen);
  
  console.log(`  Position: ${finding.position}, Severity: ${finding.severity}`);
  console.log(`  Actual priority: ${finding.priority}`);
  console.log(`  Expected (with override): ${correctScore}`);
  console.log(`  Would be (bug scenario): ${driftedScore}`);
  console.log(`  Drift delta: ${correctScore - driftedScore} points`);
  
  if (finding.priority === correctScore) {
    console.log("  ✓ PASS: Correct priority with bidi-control override");
    passCount++;
  } else {
    console.log(`  ✗ FAIL: Priority mismatch (got ${finding.priority}, expected ${correctScore})`);
    failCount++;
  }
}

console.log(`\n=== Summary ===`);
console.log(`Passed: ${passCount}/${testCases.length}`);
console.log(`Failed: ${failCount}/${testCases.length}`);

if (failCount === 0) {
  console.log("\n✓ CONFIRMED: 12-point drift is RESOLVED");
  console.log("✓ All bidi-control findings score at 1.20 multiplier");
  process.exit(0);
} else {
  console.log("\n✗ ISSUE: Drift not fully resolved");
  process.exit(1);
}
