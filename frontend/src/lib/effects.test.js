import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// An effect that is written as an expression (useEffect(() => something(), [...])) returns that expression's value.
// React treats any non-function return value as a cleanup function and crashes with "destroy is not a function".
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const files = [];
(function walk(dir) {
  for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, f.name);
    if (f.isDirectory()) walk(p);
    else if (/\.jsx?$/.test(f.name) && !/\.test\./.test(f.name)) files.push(p);
  }
})(root);

test("no useEffect/useLayoutEffect uses an expression body", () => {
  const bad = [];
  for (const f of files) {
    const src = fs.readFileSync(f, "utf8");
    for (const m of src.matchAll(/use(?:Layout)?Effect\(\s*(?:async\s*)?\(\)\s*=>\s*([^{\s])/g)) {
      bad.push(`${path.relative(root, f)}: ${m[0]}`);
    }
  }
  assert.deepEqual(bad, []);
});

test("the scan itself works (it finds a deliberately bad example)", () => {
  const sample = "useEffect(() => el.scrollIntoView(), [x]);";
  assert.ok(/use(?:Layout)?Effect\(\s*(?:async\s*)?\(\)\s*=>\s*([^{\s])/.test(sample));
});
