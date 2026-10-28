import json, hashlib
import qrcode
from qrcode.util import QRData, MODE_NUMBER, MODE_8BIT_BYTE
from mnemonic import Mnemonic
import zxingcpp
from PIL import Image
m = Mnemonic("english")
wl = m.wordlist
ents = [bytes(16), bytes([0x7f])*16, bytes([0xff])*16, bytes([0x80])+bytes(15), bytes(32), bytes([0x7f])*32, bytes([0xff])*32]
for i in range(6):
    ents.append(hashlib.sha256(b"voidforge-seedqr-%d" % i).digest()[:16 if i % 2 == 0 else 32])
out = []
for e in ents:
    words = m.to_mnemonic(e)
    ws = words.split()
    digits = "".join("%04d" % wl.index(w) for w in ws)
    rec = {"words": words, "digits": digits, "entropy": e.hex(), "formats": {}}
    for name, data, mode in (("seedqr", digits, MODE_NUMBER), ("compact", e, MODE_8BIT_BYTE)):
        hashes = []; ver = None
        for mask in range(8):
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_L, border=0, box_size=1, mask_pattern=mask)
            qr.add_data(QRData(data, mode=mode)); qr.make(fit=True)
            mat = qr.get_matrix(); ver = qr.version
            s = "".join("".join("1" if c else "0" for c in row) for row in mat)
            hashes.append(hashlib.sha256(s.encode()).hexdigest())
            if mask == 0:
                n = len(mat); S = 8; q = 4
                img = Image.new("L", ((n + 2*q) * S, (n + 2*q) * S), 255)
                px = img.load()
                for y in range(n):
                    for x in range(n):
                        if mat[y][x]:
                            for dy in range(S):
                                for dx in range(S): px[(x+q)*S+dx, (y+q)*S+dy] = 0
                res = zxingcpp.read_barcodes(img)
                assert len(res) == 1, (name, len(res))
                got = res[0].bytes if mode == MODE_8BIT_BYTE else res[0].text.encode()
                want = e if mode == MODE_8BIT_BYTE else digits.encode()
                assert got == want, (name, got, want)
        qa = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_L, border=0, box_size=1)
        qa.add_data(QRData(data, mode=mode)); qa.make(fit=True)
        sa = "".join("".join("1" if c else "0" for c in row) for row in qa.get_matrix())
        auto = hashlib.sha256(sa.encode()).hexdigest()
        assert auto in hashes
        rec["formats"][name] = {"version": ver, "size": ver * 4 + 17, "hashes": hashes, "auto": auto}
    out.append(rec)
json.dump(out, open("seedqr.json", "w"), indent=0)
print(len(out), "phrases;", [(r["words"].count(" ")+1, r["formats"]["seedqr"]["size"], r["formats"]["compact"]["size"]) for r in out])
