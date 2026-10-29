# Appends long QR cases (versions 13-30, error correction M, byte mode) to qr.json, made with the independent Python
# `qrcode` library (all 8 masks hashed) and read back with zxing-cpp. Run from tests/fixtures: python3 gen_qr_long.py
import json, hashlib
import qrcode
import zxingcpp
from PIL import Image
CAP = {13:331,14:362,15:412,16:450,17:504,18:560,19:624,20:666,21:711,22:779,23:857,24:911,25:997,26:1059,27:1125,28:1190,29:1264,30:1370}
def text(n, tag):
    s = ""; i = 0
    while len(s) < n: s += hashlib.sha256(b"%s-%d" % (tag, i)).hexdigest(); i += 1
    return s[:n]
fx = json.load(open("qr.json"))
fx = [c for c in fx if c["version"] <= 12]
for v, cap in CAP.items():
    for n in (cap, CAP.get(v-1, 287) + 1):
        t = text(n, b"qrlong%d" % v)
        hashes = []; ver = None
        for mask in range(8):
            q = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, border=0, box_size=1, mask_pattern=mask)
            q.add_data(t); q.make(fit=True); mat = q.get_matrix(); ver = q.version
            hashes.append(hashlib.sha256("".join("".join("1" if c else "0" for c in r) for r in mat).encode()).hexdigest())
            if mask == 0:
                N = len(mat); S = 4; pad = 4
                img = Image.new("L", ((N + 2*pad) * S, (N + 2*pad) * S), 255); px = img.load()
                for y in range(N):
                    for x in range(N):
                        if mat[y][x]:
                            for dy in range(S):
                                for dx in range(S): px[(x+pad)*S+dx, (y+pad)*S+dy] = 0
                res = zxingcpp.read_barcodes(img)
                assert len(res) == 1 and res[0].text == t, (v, n)
        assert ver == v, (v, n, ver)
        fx.append({"text": t, "version": ver, "hashes": hashes})
json.dump(fx, open("qr.json", "w"), indent=0)
print(len(fx), "cases")
