// Automated checks for voidforge.html. Run: npm i jsdom && node tests/test.js [path/to/voidforge.html]
const {JSDOM}=require('jsdom'); const fs=require('fs'); const path=require('path'); const nc=require('crypto');
const file=process.argv[2]||path.join(__dirname,'..','voidforge.html');
const html=fs.readFileSync(file,'utf8');
let failed=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) failed++; };
const eq=(a,b,m)=>ok(a===b, m+(a===b?'':` (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`));

function load(opts={}){ 
  const errors=[]; const st={blob:null,printed:0,clip:[],confirms:0,alerts:[]};
  const dom=new JSDOM(html,{runScripts:'dangerously',pretendToBeVisual:true,url:'https://example.org/',
    beforeParse(w){
      Object.defineProperty(w,'crypto',{value:nc.webcrypto});
      if(!w.TextEncoder) w.TextEncoder=TextEncoder; if(!w.TextDecoder) w.TextDecoder=TextDecoder; // older jsdom omits these; real browsers have them
      w.alert=m=>st.alerts.push(m); w.confirm=()=>{st.confirms++;return opts.confirm!==false;};
      w.addEventListener('error',e=>errors.push(e.message));
      w.URL.createObjectURL=b=>{st.blob=b;return 'blob:x';}; w.URL.revokeObjectURL=()=>{};
      w.HTMLAnchorElement.prototype.click=function(){};
      w.print=()=>{ st.printed++; st.printHTML=w.document.getElementById('printOnly').textContent; st.printClass=w.document.body.className; };
      Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async t=>{st.clip.push(t);}}});
    }});
  const w=dom.window; return {w,ready:()=>w.selfTestDone,d:w.document,$:id=>w.document.getElementById(id),st,errors,
    set(v){ this.$('rolls').value=v; this.$('rolls').oninput(); },
    mode(m){ const e=this.d.querySelector(`input[name=mode][value=${m}]`); e.checked=true; e.onchange(); },
    words(n){ const e=this.d.querySelector(`input[name=words][value="${n}"]`); e.checked=true; e.onchange(); }};
}
const blobText=(w,b)=>b.text?b.text():new Promise((res,rej)=>{const r=new w.FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsText(b);});
const rnd=(n,k)=>Array.from({length:n},()=>String(k===2?nc.randomInt(2):1+nc.randomInt(6))).join('');

(async()=>{
  let t=load(); await t.ready(); await t.ready();
  // --- self-test (known-answer vectors) ---
  await t.w.runSelfTests();
  ok(/^ALL \d+ TESTS PASSED/.test(t.$('testResults').textContent),'in-page SELF-TEST passes: '+t.$('testResults').textContent.split('\n')[0]);
  // --- RIPEMD-160 fuzz vs Node ---
  let bad=0; for(let n=0;n<300;n++){ const b=nc.randomBytes(n<130?n:nc.randomInt(0,2000));
    if(Buffer.from(t.w.ripemd160(new t.w.Uint8Array(b))).toString('hex')!==nc.createHash('ripemd160').update(b).digest('hex')) bad++; }
  eq(bad,0,'RIPEMD-160 fuzz mismatches');
  // --- dice flow, SeedSigner published example ---
  t.set('65515223131652132161133154444123616466443112153441'); await t.w.generate();
  eq(t.$('genResult').textContent,'hole luggage safe present express tragic orbit shed switch metal identify path','dice 50 rolls -> SeedSigner mnemonic');
  ok(/8d9cced8/.test(t.$('fingerprint').textContent),'dice 50 rolls -> SeedSigner fingerprint');
  // --- passphrase: masked, not shown/copied/printed/saved ---
  eq(t.$('passphrase').type,'password','passphrase input is masked');
  t.$('passphrase').value='TREZOR'; t.$('passphrase2').value='TREZORX'; await t.w.generate();
  ok(/do not match/.test(t.$('genResult').textContent)&&t.$('fingerprint').textContent===''&&t.$('address').textContent==='','mismatched passphrase boxes block FORGE and show no fingerprint or address');
  t.$('passphrase2').value='TREZOR'; await t.w.generate();
  ok(/bc1q[0-9a-z]{38}/.test(t.$('address').textContent)&&/\(with passphrase\)/.test(t.$('address').textContent),'first receive address shown (with passphrase)');
  ok(/f00e80ca \(with passphrase\)/.test(t.$('fingerprint').textContent),'fingerprint reflects passphrase');
  ok(!t.$('genResult').textContent.includes('TREZOR'),'passphrase text not shown in result');
  // --- coin mode 1/0 ---
  t.mode('coin'); const C128="01001110000101011011111010111010111101101111110000011010011111111011000111011111011101110110111001010001000001100110010101001110";
  t.set(C128); await t.w.generate();
  ok(t.$('genResult').textContent.startsWith('trigger soccer priority image feature romance whisper jar crush sleep super potato'),'coin 128 flips (1/0) vector');
  t.set('HTHT'+C128.slice(0,50)); eq(t.$('rollCount').textContent.split(' ')[0],'50','letters ignored in coin mode');
  t.set('1'.repeat(128)); ok(/non-random/.test(t.$('entropyStatus').textContent),'all-ones flagged as non-random');
  // --- hardening: attributes ---
  for(const id of ['rolls','phrase','passphrase','note']){
    const e=t.$(id); ok(e.getAttribute('spellcheck')==='false'&&e.getAttribute('autocomplete')&&e.getAttribute('autocapitalize')==='off',`#${id} has spellcheck/autocomplete/autocapitalize off`);
  }
  // --- online banner ---
  ok(t.$('onlineWarn').style.display==='block'&&/ONLINE/.test(t.$('onlineWarn').textContent),'online banner shown when navigator.onLine');
  Object.defineProperty(t.w.navigator,'onLine',{value:false,configurable:true}); t.w.dispatchEvent(new t.w.Event('offline'));
  eq(t.$('onlineWarn').style.display,'none','online banner hides when offline');
  // --- passphrase toggle ---
  const btn=[...t.d.querySelectorAll('button')].find(b=>b.textContent==='SHOW'); t.w.togglePassphrase(btn);
  ok(t.$('passphrase').type==='text'&&btn.textContent==='HIDE','passphrase SHOW toggles visibility');
  t=load(); await t.ready(); t.set(rnd(50)); await t.w.generate();
  // --- print: only words + fingerprint, never passphrase, cleans up ---
  t=load(); await t.ready(); t.set(rnd(50)); t.$('passphrase').value='SECRETPASS'; t.$('passphrase2').value='SECRETPASS'; await t.w.generate();
  const words=t.$('genResult').textContent.split('\n')[0];
  t.w.printSeed();
  ok(t.st.printed===1&&t.st.printHTML.includes(words)&&!t.st.printHTML.includes('SECRETPASS')&&/print-seed/.test(t.st.printClass),'PRINT SEED prints words+fingerprint only, no passphrase');
  t.w.dispatchEvent(new t.w.Event('afterprint')); ok(t.$('printOnly').textContent===''&&!t.d.body.classList.contains('print-seed'),'print area cleaned up after printing');
  // --- download seed: confirm, no passphrase ---
  t.w.downloadSeed(); const txt=await blobText(t.w,t.st.blob);
  ok(t.st.confirms>=2&&txt.includes(words)&&!txt.includes('SECRETPASS'),'DOWNLOAD seed asks first and omits passphrase');
  // --- download tool: clean copy, no seed ---
  t.w.downloadTool(); const page=await blobText(t.w,t.st.blob);
  ok(!page.includes(words.split(' ').slice(0,4).join(' ')),'DOWNLOAD FOR USB copy contains no generated seed');
  ok(!page.includes('SECRETPASS'),'DOWNLOAD FOR USB copy contains no passphrase');
  // --- clear wipes everything ---
  t.$('phrase').value='abandon '.repeat(11)+'about'; await t.w.verify(); await t.w.runSelfTests(); t.w.clearAll(); await new Promise(r=>setTimeout(r,20));
  ok(t.$('phrase').value===''&&t.$('verifyStatus').textContent===''&&t.$('testResults').textContent===''&&t.$('genResult').textContent==='—'&&t.$('passphrase').value==='','CLEAR wipes rolls, passphrase, verify box, results');
  ok(t.st.clip.includes(''),'CLEAR attempts to clear the clipboard');

  // ===== v1.1 additions =====
  t=load(); await t.ready();
  ok(/SELF-TEST PASSED/.test(t.$('selfTestBadge').textContent)&&!t.$('forgeBtn').disabled&&!t.$('verifyBtn').disabled,'auto self-test runs on load and enables the tool');
  // v1.4: address, passphrase confirm, tap buttons
  { t.set('65515223131652132161133154444123616466443112153441'); t.$('passphrase').value=''; t.$('passphrase2').value=''; await t.w.generate();
    ok(/bc1q[0-9a-z]{38}/.test(t.$('address').textContent),'first receive address is shown after FORGE');
    ok(!/with passphrase/.test(t.$('address').textContent),'no passphrase label when no passphrase');
    const st=t.$('genResult').textContent; t.$('passphrase').value='x'; t.$('passphrase2').value=''; await t.w.generate(); ok(/do not match/.test(t.$('genResult').textContent),'passphrase vs empty confirm is a mismatch');
    t.$('passphrase').value=''; t.$('passphrase2').value='';
    t.$('phrase').value='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'; await t.w.verify();
    ok(/bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/.test(t.$('verifyStatus').textContent),'VERIFY shows the published BIP84 first address for abandon...about');
    // VERIFY with and without a passphrase
    t.$('verifyPass').value='TREZOR'; await t.w.verify(); { const vs=t.$('verifyStatus').textContent;
      ok(/Without passphrase: fingerprint 73c5da0a \| first address bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/.test(vs),'VERIFY shows the without-passphrase fingerprint and address');
      ok(/With passphrase \(6 characters, not shown\): fingerprint b4e3f5ed \| first address bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu/.test(vs)&&!vs.includes('TREZOR'),'VERIFY shows the with-passphrase fingerprint and address without revealing the passphrase'); }
    t.$('verifyPass').value=''; await t.w.verify(); ok(/No passphrase entered/.test(t.$('verifyStatus').textContent)&&!/With passphrase/.test(t.$('verifyStatus').textContent),'VERIFY without a passphrase says none was entered');
    t.$('verifyPass').value='TREZOR'; t.w.toggleVerifyPassphrase(t.d.querySelector('button[onclick^="toggleVerifyPassphrase"]')); ok(t.$('verifyPass').type==='text','VERIFY passphrase SHOW toggle works'); t.w.toggleVerifyPassphrase(t.d.querySelector('button[onclick^="toggleVerifyPassphrase"]'));
    t.$('verifyPass').value='';
    t.$('rolls').value=''; t.w.updateCount();
    const taps=[...t.d.querySelectorAll('#tapRow button')]; ok(taps.length===6,'six dice tap buttons in dice mode');
    taps[0].onclick(); taps[5].onclick(); taps[2].onclick(); eq(t.$('rolls').value,'163','tap buttons append rolls and update the counter'); ok(/3 \/ 50/.test(t.$('rollCount').textContent),'counter updates after taps');
    const coin=t.d.querySelector('input[name="mode"][value="coin"]'); t.$('rolls').value=''; coin.checked=true; t.w.onModeChange();
    const ct=[...t.d.querySelectorAll('#tapRow button')]; ok(ct.length===2&&ct[0].textContent==='1'&&ct[1].textContent==='0','coin mode shows 1 and 0 tap buttons');
    ct[1].onclick(); ct[0].onclick(); eq(t.$('rolls').value,'01','coin taps append flips');
    const dice=t.d.querySelector('input[name="mode"][value="dice"]'); t.$('rolls').value=''; dice.checked=true; t.w.onModeChange();
    t.$('passphrase').value='a'; t.$('passphrase2').value='a'; t.w.togglePassphrase(t.d.querySelector('button[onclick^="togglePassphrase"]')); ok(t.$('passphrase').type==='text'&&t.$('passphrase2').type==='text','SHOW reveals both passphrase boxes');
  }
  // item 1: patterns
  ok(t.$('noJs').style.display==='none','script-not-running notice is hidden once the script has run');
  ok(/DICE \/ COIN ENTROPY/.test(t.d.querySelector('.subtitle').textContent),'header says dice / coin');
  ok(t.$('coinHint').style.display==='none','coin hint hidden in dice mode');
  { const coin=t.d.querySelector('input[name="mode"][value="coin"]'); coin.checked=true; t.w.onModeChange(); ok(t.$('coinHint').style.display==='block'&&/heads = 1/.test(t.$('coinHint').textContent),'coin mode shows which side is 1 and to record the string'); const dice=t.d.querySelector('input[name="mode"][value="dice"]'); dice.checked=true; t.w.onModeChange(); ok(t.$('coinHint').style.display==='none','coin hint hides again in dice mode'); }
  ok(/^NETWORK: (ONLINE|OFFLINE)/.test(t.$('netTag').textContent),'network tag is always visible');
  t.$('rolls').value='1'.repeat(0)+'123456'.repeat(8)+'12'; t.$('rolls').oninput();
  ok(/\u2248 129 bits/.test(t.$('bitsNote').textContent)&&/IF every roll was fair/.test(t.$('bitsNote').textContent),'bits note shows about 129 bits for 50 rolls with fairness caveat');
  t.$('rolls').value=''; t.$('rolls').oninput();
  ok(t.$('bitsNote').textContent==='','bits note empty with no input');
  const pat={'123456 repeated':['123456'.repeat(9),'dice'],'sorted blocks':['1'.repeat(10)+'2'.repeat(10)+'3'.repeat(10)+'4'.repeat(10),'dice'],'25x1+25x6':['1'.repeat(25)+'6'.repeat(25),'dice']};
  for(const [k,[v]] of Object.entries(pat)){ t.set(v); ok(/non-random/.test(t.$('entropyStatus').textContent),'pattern flagged: '+k); }
  t.set('65515223131652132161133154444123616466443112153441'); ok(/No obvious problems/.test(t.$('entropyStatus').textContent),'SeedSigner example input not flagged');
  t.set('1'.repeat(50)); t.$('forgeBtn').onclick=null; t.st.confirms=0;
  const tc=load({confirm:false}); await tc.ready(); tc.set('123456'.repeat(9).slice(0,50)); tc.d.querySelector('input[name=words][value="12"]').checked=true; await tc.w.generate();
  ok(tc.st.confirms===1&&tc.$('genResult').textContent==='—','FORGE on non-random input asks first and can be cancelled');
  // item 2: no crypto.subtle
  { const errs=[]; const dom=new (require('jsdom').JSDOM)(html,{runScripts:'dangerously',url:'https://x.org/',beforeParse(w){Object.defineProperty(w,'crypto',{value:{}});if(!w.TextEncoder)w.TextEncoder=TextEncoder;w.alert=m=>errs.push(m);w.addEventListener('error',e=>errs.push(e.message));}});
    await new Promise(r=>setTimeout(r,50)); const d=dom.window.document;
    ok(d.getElementById('fatalWarn').style.display==='block'&&d.getElementById('forgeBtn').disabled,'missing crypto.subtle: red banner shown, FORGE disabled');
    ok(!errs.some(e=>/Cannot read/.test(e)),'missing crypto.subtle: no uncaught exception'); }
  // item 3: failed self-test disables the tool (tamper the wordlist)
  { const bad=html.replace('"abandon","ability"','"abandon","abilityX"'); const dom=new (require('jsdom').JSDOM)(bad,{runScripts:'dangerously',url:'https://x.org/',beforeParse(w){Object.defineProperty(w,'crypto',{value:nc.webcrypto});if(!w.TextEncoder)w.TextEncoder=TextEncoder;w.alert=()=>{};}});
    await dom.window.selfTestDone; const d=dom.window.document;
    ok(/FAILED/.test(d.getElementById('selfTestBadge').textContent)&&d.getElementById('forgeBtn').disabled&&d.getElementById('verifyBtn').disabled,'tampered wordlist: self-test fails and tool is disabled'); }
  // item 4: ignored characters + mode switch
  t.set('1234 5670 89'); ok(/Ignored 4 invalid/.test(t.$('ignoredNote').textContent),'invalid characters are reported: '+t.$('ignoredNote').textContent);
  t.set('123456'); let c=t.d.querySelector('input[name=mode][value=coin]'); c.checked=true; c.onchange(); ok(t.$('rolls').value==='','mode switch clears entered rolls');
  const tm=load({confirm:false}); await tm.ready(); tm.set('123456'); c=tm.d.querySelector('input[name=mode][value=coin]'); c.checked=true; c.onchange();
  ok(tm.$('rolls').value==='123456'&&tm.d.querySelector('input[name=mode][value=dice]').checked,'cancelling a mode switch keeps rolls and mode');
  // item 5 & 6: CSP, no links
  ok(/Content-Security-Policy/.test(html)&&/default-src 'none'/.test(html),'CSP meta present with default-src none');
  ok(!/<a\s/i.test(html.replace(/const WORDLIST = \[.*?\];/s,'')),'page contains no links');
  // v1.2: only 12/24 words, no copy-seed button
  eq([...t.d.querySelectorAll('input[name=words]')].map(e=>e.value).join(','),'12,24','only 12 and 24 word options are offered');
  ok(![...t.d.querySelectorAll('button')].some(b=>/COPY SEED/.test(b.textContent))&&typeof t.w.copyResult==='undefined','no copy-seed button or function');
  { let threw=false; try{ await t.w.rollsToMnemonic('1'.repeat(62),15);}catch(e){threw=true;} ok(threw,'15-word generation is rejected'); }
  ok(/Recovery notes/.test(html)&&/move the funds/.test(html),'changelog has recovery notes for removed modes');
  ok((await t.w.checkPhrase('abandon '.repeat(14)+'address')).ok,'VERIFY still accepts 15-word phrases from other tools');
  { const tcn=load(); await tcn.ready(); tcn.mode('coin'); tcn.set('0101'); await tcn.w.generate(); ok(/flips/.test(tcn.$('genResult').textContent)&&!/rolls/.test(tcn.$('genResult').textContent),'coin-mode length message says flips'); }
  { const ts=load(); await ts.ready(); ts.set(rnd(50)); await ts.w.generate(); const w0=ts.$('genResult').textContent.split('\n')[0];
    await ts.w.sendToVerify();
    ok(ts.$('phrase').value===w0&&/Valid 12-word/.test(ts.$('verifyStatus').textContent),'SEND TO VERIFY fills the VERIFY box and validates the seed');
    ok(ts.st.clip.length===0,'SEND TO VERIFY does not touch the clipboard');
    const te=load(); await te.ready(); await te.w.sendToVerify(); ok(te.st.alerts.length===1&&te.$('phrase').value==='','SEND TO VERIFY with no seed alerts and does nothing'); }
  // item 8: changelog
  ok(/Changelog/.test(html)&&/Breaking/.test(html),'changelog documents the H/T breaking change');

  // --- no network / external references ---
  const src=html.replace(/const WORDLIST = \[.*?\];/s,'');
  ok(!/fetch\(|XMLHttpRequest|WebSocket|sendBeacon|<script[^>]+src=|<link|@import/.test(src),'no network APIs or external resources');
  const urls=[...src.matchAll(/https?:\/\/[^\s"'<>)]+/g)].map(m=>m[0]); ok(urls.every(u=>u.startsWith('https://github.com/Random21m/voidforge')),'only URL is the GitHub link: '+urls.join(', '));
  ok(t.errors.length===0,'no uncaught page errors '+JSON.stringify(t.errors));
  console.log(failed?`\n${failed} CHECK(S) FAILED`:'\nALL CHECKS PASSED'); process.exit(failed?1:0);
})();
