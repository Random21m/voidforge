// Shared helpers for the oracle and mutation tests (ESM).
import { JSDOM } from 'jsdom';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import nc from 'node:crypto';

export const HTML_PATH = process.argv.find(a => a.endsWith('.html')) ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'voidforge.html');
export const readHtml = () => fs.readFileSync(HTML_PATH, 'utf8');

export function loadPage(html, pre) {
  const dom = new JSDOM(html, {
    runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://example.org/',
    beforeParse(w) {
      Object.defineProperty(w, 'crypto', { value: nc.webcrypto });
      if (!w.TextEncoder) w.TextEncoder = TextEncoder;   // older jsdom omits these; real browsers have them
      if (!w.TextDecoder) w.TextDecoder = TextDecoder;
      w.alert = () => {}; w.confirm = () => true;
      w.HTMLAnchorElement.prototype.click = function () {};
      if (pre) pre(w);
    },
  });
  return dom.window;
}
export const ready = async (w) => { await w.selfTestDone; return w; };
export const rnd = (n, k) => Array.from({ length: n }, () => String(k === 2 ? nc.randomInt(2) : 1 + nc.randomInt(6))).join('');

export function makeReporter() {
  let failed = 0, passed = 0;
  return {
    ok(cond, msg) { console.log((cond ? 'PASS ' : 'FAIL ') + msg); cond ? passed++ : failed++; },
    done(label) { console.log(`\n${label}: ${passed} passed, ${failed} failed`); process.exit(failed ? 1 : 0); },
  };
}
