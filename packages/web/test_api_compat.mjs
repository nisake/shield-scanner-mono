import { analyze } from '@shield-scanner/core';

// Test 1: New API (object)
const result1 = analyze("Hello​World", { fileType: "text" });
console.log("New API (object): OK");
console.log("  Result keys:", Object.keys(result1));

// Test 2: Old API (string) — this is what app.js is using!
try {
  const result2 = analyze("Hello​World", "text");
  console.log("Old API (string): OK");
  console.log("  Result keys:", Object.keys(result2));
} catch (e) {
  console.log("Old API (string): ERROR");
  console.log("  Error:", e.message);
}
