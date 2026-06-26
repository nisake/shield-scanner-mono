import { analyze } from '@shield-scanner/core';

const rloInput = "normal text ‮ reversed";
const result = analyze(rloInput, { fileType: "text" });

const bidi = (result.findings.invisibleUnicode || []).filter(f => f.category === "bidi-control");
if (bidi.length === 0) {
  console.log("ERROR: No bidi findings!");
  process.exit(1);
}

const finding = bidi[0];
console.log("Bidi-control finding from analyze():");
console.log("  name:", finding.name);
console.log("  category:", finding.category);
console.log("  priority:", finding.priority);
console.log("  priorityReason:", finding.priorityReason);

if (typeof finding.priority === "number") {
  console.log("\n✓ CONFIRMED: analyze() attaches priority to findings");
} else {
  console.log("\n✗ ERROR: analyze() did NOT attach priority field");
  process.exit(1);
}
