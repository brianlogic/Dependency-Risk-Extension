import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { rewriteNpmManifest, rewritePythonManifest, type TextEdit } from "../src/commands/rewriteSpec";

const apply = (text: string, ...edits: (TextEdit | undefined)[]) =>
  edits.reduce((t, e) => (e ? t.slice(0, e.start) + e.text + t.slice(e.end) : t), text);

describe("safe fix rewrites", () => {
  it("keeps npm range prefixes and skips non-simple specs", () => {
    const text = '{"dependencies":{"a":"^1.2.3","b":"git+https://x","c":"1.0.0"},"devDependencies":{"a":"~1.0.0"}}';
    assert.equal(apply(text, ...rewriteNpmManifest(text, "a", "1.2.9")), text.replace('"^1.2.3"', '"^1.2.9"').replace('"~1.0.0"', '"~1.2.9"'));
    assert.deepEqual(rewriteNpmManifest(text, "b", "2.0.0"), []);
    assert.match(apply(text, ...rewriteNpmManifest(text, "c", "1.0.1")), /"c":"1\.0\.1"/);
  });

  it("rewrites requirements.txt and pyproject lines", () => {
    const req = "flask[async]==2.0.0 ; python_version>'3'  # web\nrequests>=2.0,<3\n";
    assert.match(apply(req, rewritePythonManifest(req, "requirements.txt", "flask", "2.3.3")), /^flask\[async\]==2\.3\.3 ;/);
    assert.equal(rewritePythonManifest(req, "requirements.txt", "requests", "2.31.0"), undefined);
    const toml = 'dependencies = [\n  "Django>=3.2",\n]\n';
    assert.match(apply(toml, rewritePythonManifest(toml, "pyproject.toml", "django", "4.2.1")), /"Django>=4\.2\.1"/);
  });
});
