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
      w.print=()=>{ st.printed++; st.printHTML=w.document.getElementById('printOnly').textContent; st.printClass=w.document.body.className; st.printQrText=w.document.getElementById('printQr').textContent; st.printQrHTML=w.document.getElementById('printQr').innerHTML; };
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
  // address finder
  { const AB='abandon '.repeat(11)+'about'; t.$('phrase').value=AB; t.$('verifyPass').value='';
    const C=async(x,r)=>{ t.$('checkAddr').value=x; await t.w.checkAddress(r); return [t.$('addrCheckStatus').textContent,t.$('addrCheckStatus').className]; };
    let [tx,cl]=await C('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',4); ok(/^FOUND: this SegWit address is receive address #0 \(m\/84'\/0'\/0'\/0\/0\)/.test(tx)&&/ok/.test(cl),'address finder: SegWit receive #0 found');
    [tx,cl]=await C('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g',4); ok(/receive address #1 /.test(tx),'address finder: SegWit receive #1 found');
    [tx,cl]=await C('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',4); ok(/^FOUND: this Taproot address is receive address #0 \(m\/86'\/0'\/0'\/0\/0\)/.test(tx),'address finder: Taproot receive #0 found');
    [tx,cl]=await C('bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7',4); ok(/change address #0 /.test(tx),'address finder: Taproot change #0 found');
    [tx,cl]=await C('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',4); ok(/^NOT FOUND in indices 0 to 3 /.test(tx)&&/bad/.test(cl),'address finder: another address is NOT FOUND');
    [tx,cl]=await C('hello',4); ok(/Enter a bc1q/.test(tx),'address finder: rejects text that is not an address');
    t.$('phrase').value='abandon abandon'; [tx,cl]=await C('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',4); ok(/valid seed phrase/.test(tx),'address finder: needs a valid phrase');
    t.$('phrase').value=''; t.$('checkAddr').value=''; t.$('addrCheckStatus').textContent=''; }
  // SeedQR / CompactSeedQR input and BIP85 child seeds
  { const AB='abandon '.repeat(11)+'about'; const V=async x=>{ t.$('phrase').value=x; await t.w.verify(); return [t.$('verifyStatus').textContent.split('\n')[0], t.$('phrase').value]; };
    let [m,box]=await V('0000'.repeat(11)+'0003'); ok(/^Valid 12-word BIP39 phrase \(read from a SeedQR digit string\)/.test(m)&&box===AB,'VERIFY reads a SeedQR digit string and shows the words');
    [m,box]=await V('7f'.repeat(16)); ok(/CompactSeedQR hex/.test(m)&&box==='legal winner thank year wave sausage worth useful legal winner thank yellow','VERIFY reads CompactSeedQR hex and shows the words');
    [m]=await V('2048'+'0000'.repeat(11)); ok(/above 2047/.test(m),'SeedQR number above 2047 is rejected');
    [m]=await V('0000'.repeat(12)); ok(/Checksum failed/.test(m),'SeedQR with a bad checksum is rejected');
    [m]=await V(AB); ok(/^Valid 12-word BIP39 phrase$/.test(m),'plain words still verify as before');
    t.$('phrase').value=AB; t.$('verifyPass').value=''; t.$('childWords').value='12'; t.$('childIndex').value='0';
    await t.w.deriveChild(); ok(/prosper short ramp prepare exchange stove life snack client enough purpose fold/.test(t.$('childOut').textContent.replace(/\s+/g,' ').replace(/\d+\. /g,'')),'BIP85 child seed 0 (12 words) for abandon..about');
    t.$('childIndex').value='abc'; await t.w.deriveChild(); ok(/whole number/.test(t.$('childStatus').textContent)&&t.$('childOut').textContent==='','BIP85 rejects a bad index and clears the output');
    t.$('childIndex').value='0'; await t.w.deriveChild(); t.$('childIndex').dispatchEvent(new t.w.Event('input')); ok(t.$('childOut').textContent==='','BIP85 output is cleared when the index is edited');
    t.$('phrase').value='abandon abandon'; await t.w.deriveChild(); ok(/valid parent seed phrase/.test(t.$('childStatus').textContent),'BIP85 needs a valid parent phrase');
    t.$('phrase').value=''; t.$('childOut').textContent=''; t.$('childStatus').textContent=''; t.$('verifyStatus').textContent=''; }
  // SELF-TEST button toggles: press again hides the results without CLEAR
  t.w.toggleSelfTests();
  ok(t.$('testResults').textContent==='','SELF-TEST button: press while results are shown hides them');
  await t.w.toggleSelfTests();
  ok(/^ALL \d+ TESTS PASSED/.test(t.$('testResults').textContent),'SELF-TEST button: press again shows them');
  t.w.toggleSelfTests();
  ok(t.$('testResults').textContent==='','SELF-TEST button: second press hides the results');
  // --- RIPEMD-160 fuzz vs Node ---
  let bad=0; for(let n=0;n<300;n++){ const b=nc.randomBytes(n<130?n:nc.randomInt(0,2000));
    if(Buffer.from(t.w.ripemd160(new t.w.Uint8Array(b))).toString('hex')!==nc.createHash('ripemd160').update(b).digest('hex')) bad++; }
  eq(bad,0,'RIPEMD-160 fuzz mismatches');
  // --- dice flow, SeedSigner published example ---
  t.set('65515223131652132161133154444123616466443112153441'); await t.w.generate();
  eq(t.$('genResult').textContent,'hole luggage safe present express tragic orbit shed switch metal identify path\n\nPassphrase: none','dice 50 rolls -> SeedSigner mnemonic, with an explicit "Passphrase: none" line');
  ok(/8d9cced8/.test(t.$('fingerprint').textContent),'dice 50 rolls -> SeedSigner fingerprint');
  // --- passphrase: masked, not shown/copied/printed/saved ---
  eq(t.$('passphrase').type,'password','passphrase input is masked');
  t.$('passphrase').value='TREZOR'; t.$('passphrase2').value='TREZORX'; await t.w.generate();
  ok(/do not match/.test(t.$('genResult').textContent)&&t.$('fingerprint').textContent===''&&t.$('address').textContent==='','mismatched passphrase boxes block FORGE and show no fingerprint or address');
  ok(t.$('fpIcon').textContent===''&&t.$('fpIcon').innerHTML==='','mismatched passphrase leaves no fingerprint picture showing');
  ok(t.$('watchBox').style.display==='none'&&t.$('wZpub').textContent==='','mismatched passphrase leaves no watch-only export showing');
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
  ok(t.st.printed===1&&words.split(' ').every((w,i)=>t.st.printHTML.includes(String(i+1).padStart(2,' ')+'. '+w))&&!t.st.printHTML.includes('SECRETPASS')&&/print-seed/.test(t.st.printClass),'PRINT SEED prints numbered words + fingerprint only, no passphrase');
  t.w.dispatchEvent(new t.w.Event('afterprint')); ok(t.$('printOnly').textContent===''&&!t.d.body.classList.contains('print-seed'),'print area cleaned up after printing');
  // --- SeedQR / CompactSeedQR on screen and on paper ---
  { const sz=()=>{ const v=t.$('sqImg').querySelector('svg'); return v?Math.round(v.viewBox.baseVal.width)-8:0; };
    ok(t.$('seedQrBox').style.display==='','SeedQR box appears after FORGE');
    t.w.showSeedQr('seedqr'); ok(sz()===25&&t.$('sqBox').style.display===''&&/^SeedQR for these 12 words, 25 x 25 squares/.test(t.$('sqCaption').textContent),'SEEDQR draws a 25 x 25 code for 12 words');
    t.w.showSeedQr('compact'); ok(sz()===21&&/^CompactSeedQR for these 12 words, 21 x 21 squares/.test(t.$('sqCaption').textContent),'COMPACTSEEDQR draws a 21 x 21 code for 12 words');
    t.w.hideSeedQr(); ok(t.$('sqImg').innerHTML===''&&t.$('sqBox').style.display==='none'&&t.$('sqCaption').textContent==='','HIDE removes the SeedQR');
    t.st.alerts.length=0; const p0=t.st.printed; t.w.printSeedQr(); ok(t.st.printed===p0&&/Press SHOW SEEDQR/.test(t.st.alerts.join('|')),'PRINT THIS QR needs a shown code first');
    t.w.showSeedQr('seedqr'); t.w.printSeedQr();
    ok(t.st.printed===p0+1&&/print-qr/.test(t.st.printClass)&&/VOIDFORGE SEEDQR \(12 words, 25 x 25 squares\)/.test(t.st.printQrText)&&/<svg/.test(t.st.printQrHTML)&&!t.st.printQrText.includes('SECRETPASS')&&words.split(' ').every(w=>!t.st.printQrText.includes(w+' ')),'PRINT THIS QR prints the code, no words and no passphrase');
    t.w.dispatchEvent(new t.w.Event('afterprint')); ok(t.$('printQr').textContent===''&&!t.d.body.classList.contains('print-qr'),'SeedQR print area cleaned up after printing');
    t.w.showSeedQr('compact'); t.set(rnd(50)); await t.w.generate(); ok(t.$('sqImg').innerHTML===''&&t.$('sqBox').style.display==='none','a new FORGE removes the old SeedQR');
    t.w.showSeedQr('seedqr'); t.w.clearAll(); ok(t.$('sqImg').innerHTML===''&&t.$('seedQrBox').style.display==='none','CLEAR removes the SeedQR and hides its box');
    t.st.alerts.length=0; t.w.showSeedQr('seedqr'); ok(t.$('sqImg').innerHTML===''&&/Generate a seed first/.test(t.st.alerts.join('|')),'SHOW SEEDQR needs a seed first');
    t.words(24); t.set(rnd(99)); await t.w.generate(); t.w.showSeedQr('seedqr'); ok(sz()===29&&/24 words, 29 x 29/.test(t.$('sqCaption').textContent),'SEEDQR is 29 x 29 for 24 words'); t.w.showSeedQr('compact'); ok(sz()===25,'COMPACTSEEDQR is 25 x 25 for 24 words'); t.words(12); }
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
    { const wb=t.$('watchBox'); ok(wb.style.display===''&&/^zpub[1-9A-HJ-NP-Za-km-z]{100,}$/.test(t.$('wZpub').textContent)&&/^wpkh\(\[[0-9a-f]{8}\/84h\/0h\/0h\]xpub[1-9A-HJ-NP-Za-km-z]+\/0\/\*\)#[a-z0-9]{8}$/.test(t.$('wDescR').textContent)&&/\/1\/\*\)#/.test(t.$('wDescC').textContent),'watch-only box shows zpub and receive/change descriptors after FORGE'); }
    { const set=async(ty,ne,ac)=>{ t.$('wType').value=ty; t.$('wNet').value=ne; t.$('wAcct').value=ac; await t.w.refreshWatch(); };
      await set('wpkh','test','0'); ok(/^vpub/.test(t.$('wZpub').textContent)&&/^tb1q/.test(t.$('wFirst').textContent)&&/84h\/1h\/0h/.test(t.$('wDescR').textContent)&&/Testnet|vpub/.test(t.$('wKeyLabel').textContent),'testnet native SegWit shows vpub, tb1q address and a 1h coin type');
      await set('ms-wsh','main','0'); ok(/^Zpub/.test(t.$('wZpub').textContent)&&/^\[[0-9a-f]{8}\/48h\/0h\/0h\/2h\]xpub/.test(t.$('wDescR').textContent)&&t.$('wFirstGroup').style.display==='none'&&t.$('wDescGroupC').style.display==='none'&&t.$('wQrC').style.display==='none'&&/cosigner/.test(t.$('wKeyLabel').textContent),'multisig cosigner shows Zpub with origin and hides the change descriptor and first address');
      await set('ms-sh-wsh','test','1'); ok(/^Upub/.test(t.$('wZpub').textContent)&&/\/48h\/1h\/1h\/1h\]tpub/.test(t.$('wDescR').textContent),'testnet nested multisig cosigner shows Upub and a tpub origin key');
      await set('wpkh','main','0'); ok(/^zpub/.test(t.$('wZpub').textContent)&&t.$('wFirstGroup').style.display===''&&t.$('wDescGroupC').style.display===''&&t.$('wQrC').style.display==='','going back to mainnet native SegWit restores the usual boxes'); }
    { const LW=async(x)=>{ t.$('lwInput').value=x; await t.w.findLastWords(); return [t.$('lwStatus').textContent,t.$('lwStatus').className,t.$('lwOut').textContent,t.$('lwOut').style.display]; };
      let [a,c,o,d]=await LW('abandon '.repeat(11)); ok(/^128 words complete this 12-word phrase/.test(a)&&/ok/.test(c)&&d==='block'&&o.split(/\s+/).length===128&&/(^|\s)about(\s|$)/.test(o),'last word helper lists the 128 words for 11 x abandon');
      [a,c,o,d]=await LW('abandon '.repeat(23)); ok(/^8 words complete this 24-word phrase/.test(a)&&/(^|\s)art(\s|$)/.test(o),'last word helper lists 8 words for 23 words');
      [a,c,o,d]=await LW('abandon '.repeat(10)); ok(/Type 11, 14, 17, 20 or 23/.test(a)&&/bad/.test(c)&&d==='none','last word helper rejects a wrong word count');
      [a,c,o,d]=await LW('abandon '.repeat(10)+'xyzzy'); ok(/Unknown word: xyzzy/.test(a)&&d==='none','last word helper reports an unknown word');
      await LW('abandon '.repeat(11)); t.$('lwInput').dispatchEvent(new t.w.Event('input')); ok(t.$('lwOut').textContent===''&&t.$('lwStatus').textContent==='','editing the words clears the last word list');
      await LW('abandon '.repeat(11)); t.w.clearLastWords(true); ok(t.$('lwInput').value===''&&t.$('lwOut').textContent==='','CLEAR empties the last word box and list'); }
    { const P1="cHNidP8BAHECAAAAAaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urAgAAAAD/////AqCGAQAAAAAAFgAU1L4sXWjQfnhBc67qrnReNudrsjoIRgIAAAAAABYAFKPGse5KSdnyrzs4ApdHRPupJBZKAAAAAAABAR+Q0AMAAAAAABYAFJ1pVHSjA6xtdNF5bTdS8HiVkYvSAAAiAgKYnAt2y1Y5cf3JvvMewGw1YPMknW7p5dg8V2JVluBfbxhPv3VmVAAAgAAAAIAAAACAAQAAAAMAAAAA", P2="cHNidP8BAFUCAAAAARhB+qPFBDEXmeBmw7H0eMAxgXzTM6d5etkICbpnLkhZAQAAAAD/////ASC/AgAAAAAAGXapFA7T+zB3AaajntisR/jg/BhY0ZpQiKwAAAAAAAEAdwIAAAABzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0AAAAAAP////8C4JMEAAAAAAAZdqkUHP7zVxqtW/FhdOnTmSitGlcWdpOIrDDmAgAAAAAAGXapFGcMqnnlHXjtDFg7if852cSbcZnniKwAAAAAAAA=";
      const PS=async(x)=>{ t.$('psbtInput').value=x; await t.w.runPsbt(); return [t.$('psbtStatus').textContent,t.$('psbtStatus').className,t.$('psbtOut').textContent,t.$('psbtOut').style.display]; };
      let [a,c,o,d]=await PS(P1); ok(/^Read OK/.test(a)&&/ok/.test(c)&&d==='block'&&/INPUT 0: 0\.00250000 BTC \(250000 sats\)/.test(o)&&/OUTPUT 0: 0\.00100000 BTC/.test(o)&&/OUTPUT 1: 0\.00149000 BTC/.test(o)&&/FEE: 0\.00001000 BTC \(1000 sats\)/.test(o),'PSBT inspector shows inputs, outputs and fee');
      ok(/coin abababababababababababababababababababababababababababababababab:2/.test(o)&&/finalized|0 signatures so far/.test(o),'PSBT inspector shows the coin being spent and the signature state');
      ok(/OUTPUT 1:[\s\S]*fingerprint 4fbf7566[\s\S]*change/.test(o)&&/OUTPUT 0:[\s\S]*no wallet key information/.test(o),'PSBT inspector marks the output with wallet key information as likely change');
      { const bin=Buffer.from(P1,'base64'); [a,c,o]=await PS(bin.toString('hex')); ok(/^Read OK/.test(a)&&/FEE: 0\.00001000 BTC/.test(o),'PSBT inspector accepts hex too'); }
      [a,c,o,d]=await PS(P2); ok(/INPUT 0: 0\.00190000 BTC/.test(o)&&/FEE: 0\.00010000 BTC/.test(o)&&/from 1[1-9A-HJ-NP-Za-km-z]+/.test(o),'PSBT inspector reads the amount from a full previous transaction (legacy input)');
      [a,c,o,d]=await PS('not a psbt!!'); ok(/Paste the PSBT as base64/.test(a)&&/bad/.test(c)&&d==='none','PSBT inspector rejects text that is not a PSBT');
      [a,c,o,d]=await PS(Buffer.from('hello world, this is not psbt').toString('base64')); ok(/not a PSBT/.test(a)&&d==='none','PSBT inspector rejects data without the PSBT marker');
      [a,c,o,d]=await PS(P1.slice(0,60)); ok(/cut short|damaged|No unsigned/.test(a)&&/bad/.test(c)&&d==='none','PSBT inspector rejects a cut-off PSBT');
      t.$('psbtNet').value='test'; [a,c,o]=await PS(P1); ok(/to tb1q/.test(o),'PSBT inspector shows testnet addresses when Testnet is chosen'); t.$('psbtNet').value='main';
      await PS(P1); t.$('psbtInput').dispatchEvent(new t.w.Event('input')); ok(t.$('psbtOut').textContent===''&&t.$('psbtStatus').textContent==='','editing the PSBT clears the report');
      { const F=new t.w.File([Buffer.from(P1,'base64')],'a.psbt'); await t.w.onPsbtFile(F); ok(/^Read OK/.test(t.$('psbtStatus').textContent)&&/FEE: 0\.00001000 BTC/.test(t.$('psbtOut').textContent),'PSBT inspector reads a .psbt file'); }
      { const F=new t.w.File([P1],'b.txt'); await t.w.onPsbtFile(F); ok(/^Read OK/.test(t.$('psbtStatus').textContent),'PSBT inspector reads a text file holding base64'); }
      t.w.clearPsbt(true); ok(t.$('psbtInput').value===''&&t.$('psbtOut').textContent==='','CLEAR empties the PSBT box and report'); }
    ok(/without warranty/.test(t.$('disclaimer').textContent)&&/Lost words or passphrase mean lost funds/.test(t.$('disclaimer').textContent)&&/provided &ldquo;as is&rdquo;|provided \u201cas is\u201d/.test(t.w.document.body.innerHTML.replace(/&ldquo;|&rdquo;/g,'\u201c')),'disclaimer is shown under the top warning and in Security notes');
    await new Promise(r=>setTimeout(r,50));
    { const ic=t.$('fpIcon'); ok(!!ic.querySelector('svg')&&ic.querySelectorAll('rect').length>32&&!/https?:|xmlns/.test(ic.innerHTML),'fingerprint picture (LifeHash) is drawn next to the fingerprint, with no URL or namespace in the markup'); }
    { t.w.showQr('wZpub','zpub'); const img=t.$('qrImg'); ok(t.$('qrBox').style.display===''&&img.querySelector('svg')&&img.querySelector('svg path')&&/QR code for the zpub/.test(t.$('qrCaption').textContent)&&!/https?:|xmlns/.test(img.innerHTML),'SHOW QR draws a QR code for the zpub with no URL or namespace in the markup');
      t.w.hideQr(); ok(t.$('qrBox').style.display==='none'&&t.$('qrImg').innerHTML==='','HIDE QR removes the code');
      t.w.showQr('wDescC','change descriptor'); ok(!!t.$('qrImg').querySelector('svg'),'QR code for the change descriptor also draws'); }
    const st=t.$('genResult').textContent; t.$('passphrase').value='x'; t.$('passphrase2').value=''; await t.w.generate(); ok(/do not match/.test(t.$('genResult').textContent),'passphrase vs empty confirm is a mismatch');
    t.$('passphrase').value=''; t.$('passphrase2').value='';
    t.$('phrase').value='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'; await t.w.verify();
    ok(/bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/.test(t.$('verifyStatus').textContent),'VERIFY shows the published BIP84 first address for abandon...about');
    // VERIFY with and without a passphrase
    t.$('verifyPass').value='TREZOR'; await t.w.verify(); { const vs=t.$('verifyStatus').textContent;
      ok(/Without passphrase: fingerprint 73c5da0a \| first address bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/.test(vs),'VERIFY shows the without-passphrase fingerprint and address');
      ok(/With passphrase \(6 characters, not shown\): fingerprint b4e3f5ed \| first address bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu/.test(vs)&&!vs.includes('TREZOR'),'VERIFY shows the with-passphrase fingerprint and address without revealing the passphrase'); }
    t.$('verifyPass').value=''; await t.w.verify(); ok(/No passphrase entered/.test(t.$('verifyStatus').textContent)&&!/With passphrase/.test(t.$('verifyStatus').textContent),'VERIFY without a passphrase says none was entered');
    // match a recorded fingerprint/address against with / without passphrase
    { const M=async(rec,pw)=>{ t.$('verifyPass').value=pw; t.$('verifyRecorded').value=rec; await t.w.verify(); return t.$('verifyMatch').textContent; };
      ok(/^MATCH \(without passphrase\)/.test(await M('73c5da0a','')),'recorded fingerprint without passphrase -> MATCH (without)');
      ok(/^MATCH \(with passphrase\)/.test(await M('b4e3f5ed','TREZOR')),'recorded fingerprint with passphrase -> MATCH (with)');
      ok(/^MATCH \(with passphrase\)/.test(await M('BC1QV5RMQ0KT9YZ3PM36WVZCT7P3X6MTGEHJUL0FEU ','TREZOR')),'recorded address (upper case, spaces) with passphrase -> MATCH (with)');
      ok(/^MATCH \(without passphrase\)/.test(await M('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu','TREZOR')),'recorded no-passphrase address still matches (without) when a passphrase is typed');
      ok(/^NO MATCH:/.test(await M('deadbeef','TREZOR')),'recorded value matching neither -> NO MATCH');
      ok(/^NO MATCH without a passphrase/.test(await M('b4e3f5ed',''))&&/type it in the passphrase box/.test(t.$('verifyMatch').textContent),'with-passphrase backup but no passphrase typed -> asks for the passphrase');
      ok(/^Not recognized/.test(await M('hello','')),'garbage recorded value -> not recognized');
      eq(await M('','TREZOR'),'','empty recorded box shows no match line'); }
    t.$('verifyRecorded').value='';
    t.$('verifyPass').value='TREZOR'; t.w.toggleVerifyPassphrase(t.d.querySelector('button[onclick^="toggleVerifyPassphrase"]')); ok(t.$('verifyPass').type==='text','VERIFY passphrase SHOW toggle works'); t.w.toggleVerifyPassphrase(t.d.querySelector('button[onclick^="toggleVerifyPassphrase"]'));
    t.$('verifyPass').value='';
    t.$('rolls').value=''; t.w.updateCount();
    const taps=[...t.d.querySelectorAll('#tapRow button')]; ok(taps.length===6,'six dice tap buttons in dice mode');
    ok(taps.every((b,i)=>b.querySelectorAll('svg circle').length===i+1&&b.textContent.trim()===String(i+1)),'each dice button draws a face with the right number of pips and shows its number');
    taps[0].onclick(); taps[5].onclick(); taps[2].onclick(); eq(t.$('rolls').value,'163','tap buttons append rolls and update the counter'); ok(/3 \/ 50/.test(t.$('rollCount').textContent),'counter updates after taps');
    const coin=t.d.querySelector('input[name="mode"][value="coin"]'); t.$('rolls').value=''; coin.checked=true; t.w.onModeChange();
    const ct=[...t.d.querySelectorAll('#tapRow button')]; ok(ct.length===2&&ct[0].textContent==='1'&&ct[1].textContent==='0','coin mode shows 1 and 0 tap buttons');
    ct[1].onclick(); ct[0].onclick(); eq(t.$('rolls').value,'01','coin taps append flips');
    const dice=t.d.querySelector('input[name="mode"][value="dice"]'); t.$('rolls').value=''; dice.checked=true; t.w.onModeChange();
    t.$('passphrase').value='a'; t.$('passphrase2').value='a'; t.w.togglePassphrase(t.d.querySelector('button[onclick^="togglePassphrase"]')); ok(t.$('passphrase').type==='text'&&t.$('passphrase2').type==='text','SHOW reveals both passphrase boxes');
  }
  // v1.5.0: layout and clarity
  { t.set('65515223131652132161133154444123616466443112153441'); t.$('passphrase').value=''; t.$('passphrase2').value=''; await t.w.generate();
    const cells=[...t.d.querySelectorAll('#wordGrid .wcell')];
    ok(cells.length===12&&cells[0].textContent==='1.hole'&&cells[11].textContent==='12.path'&&t.$('wordGrid').style.display==='grid','seed words show as a numbered grid');
    ok(t.$('genResult').classList.contains('sr')&&t.$('genResult').dataset.seed==='1','plain-text result is kept (screen-reader only) and flagged as a seed');
    ok(/Passphrase: none/.test(t.$('passNote').textContent)&&/Write these 12 words down in order/.test(t.$('nextStep').textContent),'visible passphrase note and next-step line');
    // mismatch: error shown, grid hidden, advanced opens, error text is NOT treated as a seed
    t.$('advanced').open=false; t.$('passphrase').value='a'; t.$('passphrase2').value='b'; t.w.updateAdvSummary(); await t.w.generate();
    ok(t.$('advanced').open===true&&t.$('wordGrid').style.display==='none'&&!t.$('genResult').dataset.seed&&/PASSPHRASE SET/.test(t.$('advSummary').textContent),'mismatch opens Advanced options, hides the grid and flags the passphrase');
    t.st.alerts.length=0; await t.w.sendToVerify(); t.w.printSeed(); t.w.downloadSeed();
    ok(t.st.alerts.length===3&&t.$('phrase').value!==t.$('genResult').textContent.split('\n')[0].trim(),'after a mismatch SEND TO VERIFY, PRINT and DOWNLOAD refuse (error text is never used as a seed)');
    t.$('passphrase').value=''; t.$('passphrase2').value=''; t.w.updateAdvSummary(); ok(!/PASSPHRASE SET/.test(t.$('advSummary').textContent),'advanced summary flag clears');
    t.$('rolls').value='123'; t.w.updateCount(); await t.w.generate(); eq(t.$('genResult').textContent,'Enter 47 more rolls (3 of 50).','too few rolls: plain message');
    t.$('rolls').value='1'.repeat(53); t.w.updateCount(); await t.w.generate(); eq(t.$('genResult').textContent,'Remove 3 rolls (53 of 50).','too many rolls: plain message');
    t.$('rolls').value='1'.repeat(49); t.w.updateCount(); await t.w.generate(); eq(t.$('genResult').textContent,'Enter 1 more roll (49 of 50).','one roll short: singular');
    t.$('rolls').value='1'.repeat(51); t.w.updateCount(); await t.w.generate(); eq(t.$('genResult').textContent,'Remove 1 roll (51 of 50).','one roll over: singular');
    // roll chart: counts per face, display only
    t.$('rolls').value=''; t.w.updateCount(); eq(t.$('rollChart').style.display,'none','chart hidden when empty');
    t.$('rolls').value='1122223 6x6 6'; t.w.updateCount();
    const nums=[...t.$('rollChart').querySelectorAll('.rc-num')].map(e=>e.textContent).join(',');
    eq(nums,'2,4,1,0,0,3','chart counts per dice face (1..6), ignoring invalid characters');
    eq(t.$('rollChart').querySelectorAll('.rc-bar').length,6,'chart has six bars for dice');
    eq(t.$('rollChart').querySelectorAll('img,script,a').length,0,'chart contains no images, scripts or links');
    // five addresses, 4-letter view, guide
    t.$('rolls').value='65515223131652132161133154444123616466443112153441'; t.w.updateCount(); await t.w.generate();
    eq(t.$('addrList').querySelectorAll('li').length,5,'five receive addresses are listed after FORGE');
    ok(t.$('addrList').querySelector('li').textContent===/First receive address[^:]*: (bc1[0-9a-z]+)/.exec(t.$('address').textContent)[1],'first listed address equals the single first-address line');
    eq(t.$('addrBox').style.display,'','address list is shown after FORGE');
    { const tr=[...t.$('trList').querySelectorAll('li')].map(x=>x.textContent);
      ok(tr.length===5&&tr.every(x=>/^bc1p[0-9a-z]{58}$/.test(x))&&new Set(tr).size===5,'five distinct Taproot (bc1p) addresses are listed after FORGE');
      eq(t.$('trBox').style.display,'','Taproot list is shown after FORGE'); }
    eq(t.$('checkGuide').style.display,'','second-tool guide is shown after FORGE');
    const full=[...t.$('wordGrid').querySelectorAll('.wtxt')].map(e=>e.textContent);
    t.w.toggleAbbr();
    const abbr=[...t.$('wordGrid').querySelectorAll('.wtxt')].map(e=>e.textContent);
    ok(abbr.every((a,i)=>a===full[i].slice(0,4)),'4-letter view shows only the first four letters of each word');
    ok(new Set(abbr).size===abbr.length,'4-letter abbreviations are all distinct in this phrase');
    eq(t.$('genResult').textContent.split('\n')[0],full.join(' '),'4-letter view does not change the stored phrase');
    t.w.toggleAbbr();
    ok([...t.$('wordGrid').querySelectorAll('.wtxt')].map(e=>e.textContent).join(' ')===full.join(' '),'toggling again restores the full words');
    t.w.clearAll(); eq(t.$('addrBox').style.display,'none','address list is hidden after CLEAR');
    ok(t.$('statusLine').contains(t.$('netTag'))&&t.$('statusLine').contains(t.$('selfTestBadge')),'network tag and self-test badge share one status line');
    ok(/^NETWORK: (ONLINE|OFFLINE)$/.test(t.$('netTag').textContent),'network tag is short');
    t.$('rolls').value=''; t.w.updateCount();
  }
  // v1.4.2: explicit passphrase line in print and download
  { t.set('65515223131652132161133154444123616466443112153441'); t.$('passphrase').value=''; t.$('passphrase2').value=''; await t.w.generate(); t.w.printSeed();
    ok(/Passphrase used: NO/.test(t.st.printHTML),'print says Passphrase used: NO when none');
    t.$('passphrase').value='SECRETPASS'; t.$('passphrase2').value='SECRETPASS'; await t.w.generate(); t.w.printSeed();
    ok(/Passphrase used: YES/.test(t.st.printHTML)&&!t.st.printHTML.includes('SECRETPASS'),'print says Passphrase used: YES without printing it');
    t.w.downloadSeed(); const dtxt=await blobText(t.w,t.st.blob); ok(/Passphrase used: YES/.test(dtxt)&&!dtxt.includes('SECRETPASS'),'download says Passphrase used: YES without saving it');
    t.$('passphrase').value=''; t.$('passphrase2').value=''; }
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
