"""
Cetak QR skenario demo, lalu buktikan hasilnya benar-benar terpindai.

Prop fisik adalah titik kegagalan yang paling gampang dilupakan: QR yang
cantik di layar bisa gagal dibaca kamera HP di atas kertas, di bawah
lampu ruangan, dari sudut miring. Skrip ini mencetak semua QR skenario
lalu menjalankan pemeriksaan OpenCV terhadap tiap berkas — termasuk
versi yang diperkecil, diburamkan, dimiringkan, dan diredupkan, meniru
kondisi pemindaian di lokasi acara.

  python scripts/make_qr.py                        keluar ke ./props
  python scripts/make_qr.py -6.2088 106.8456       samakan dengan seed venue
  python scripts/make_qr.py --out /tmp/props       folder lain
  python scripts/make_qr.py --no-caption           tanpa keterangan tercetak

Jalankan dengan koordinat YANG SAMA seperti seed.py, supaya payload dan
jangkar di basis data bercerita hal yang sama.
"""

import os
import sys

import cv2
import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageFont

import seed   # scripts/ ada di sys.path saat skrip ini dijalankan

# Dikalibrasi, bukan ditebak — jalankan `--calibrate` untuk mengulang.
#
# Tebakan awal kami keliru: 'H' (toleransi kerusakan ~30%) justru
# PALING BURUK. Payload QRIS sepanjang ~150 karakter memaksa H naik ke
# versi 10 alias 57x57 modul, dan kerapatan itu merugikan lebih banyak
# daripada untung yang diberi koreksi galatnya — 11/18 kondisi terbaca.
# 'Q' menahan payload yang sama di versi 8 (49x49) dan mencetak 16/18,
# sambil tetap memulihkan sampai ~25% modul rusak.
#
#        EC  versi  modul  terbaca
#         L      5     37    16/18
#         M      6     41    16/18
#         Q      8     49    16/18   <- dipilih: skor puncak, EC tertinggi
#         H     10     57    11/18
ERROR_CORRECTION = qrcode.constants.ERROR_CORRECT_Q
BOX_SIZE = 16
BORDER = 4          # quiet zone; spec QR minta minimal 4 modul


def build_scenarios():
    """Payload tiap skenario demo, memakai satu sumber yang sama: seed.py."""
    w, p = seed.WARUNG, seed.PENIPU
    asli = seed.make_qr(w["nmid"], w["pan"], w["name"])
    palsu = seed.make_qr(p["nmid"], p["pan"], p["name"])

    # Varian yang menyerempet Layer 2. Disusun lewat emvco.build supaya
    # CRC-nya tetap benar — justru itu intinya: payload yang sah secara
    # sintaksis tapi berkontradiksi dengan spec.
    from qshield import emvco
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": p["pan"], "02": p["nmid"], "03": "UMI",
    })
    dasar = {"00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
             "58": "ID", "59": p["name"], "60": "BANDUNG", "61": "40257"}
    nominal = emvco.build({**dasar, "54": "250000.00"})

    acct_cacat = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": p["pan"], "02": "ID99", "03": "UMI",
    })
    nmid_cacat = emvco.build({**dasar, "26": acct_cacat})

    return [
        ("01-asli", asli, "ASLI — Warung Bu Sri",
         "Layer 1 mengenali jangkar: verified / proceed"),
        ("02-swap", palsu, "SWAP — NMID berbeda, nama ditiru",
         "Layer 1 menangkap: anomaly / cooling_off"),
        ("03-nominal", nominal, "CACAT — QR statis membawa nominal",
         "Layer 2 menangkap: kontradiksi struktural"),
        ("04-nmid", nmid_cacat, "CACAT — format Merchant ID salah",
         "Layer 2 menangkap: malformed_nmid"),
    ]


def render(payload, judul, subjudul, caption=True):
    """Bikin gambar QR siap cetak, opsional dengan keterangan di bawahnya."""
    qr = qrcode.QRCode(error_correction=ERROR_CORRECTION,
                       box_size=BOX_SIZE, border=BORDER)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    if not caption:
        return img

    pad = 90
    kanvas = Image.new("RGB", (img.width, img.height + pad), "white")
    kanvas.paste(img, (0, 0))
    d = ImageDraw.Draw(kanvas)
    try:
        f1 = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 26)
        f2 = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 19)
    except OSError:
        f1 = f2 = ImageFont.load_default()
    d.text((BORDER * BOX_SIZE, img.height - 18), judul, fill="black", font=f1)
    d.text((BORDER * BOX_SIZE, img.height + 20), subjudul, fill="#555555", font=f2)
    return kanvas


# --- Pemeriksaan keterbacaan ---------------------------------------

def _decode(arr, harapan):
    """True kalau payload terbaca dari gambar ini.

    Dua jalur dicoba dengan sengaja: detectAndDecodeMulti() kadang
    BERHASIL menemukan kode tapi mengembalikan string kosong pada QR
    rapat, sementara detectAndDecode() membacanya tanpa masalah.
    Memakai satu saja membuat pemeriksaan ini melaporkan gagal palsu —
    persis jenis kesalahan yang bikin panik sia-sia sebelum demo.
    """
    det = cv2.QRCodeDetector()
    teks, _, _ = det.detectAndDecode(arr)
    if teks == harapan:
        return True
    ok, banyak, _, _ = det.detectAndDecodeMulti(arr)
    return bool(ok) and harapan in list(banyak or [])


def _rotate(arr, derajat):
    h, w = arr.shape[:2]
    m = cv2.getRotationMatrix2D((w / 2, h / 2), derajat, 1.0)
    return cv2.warpAffine(arr, m, (w, h), borderValue=(255, 255, 255))


# Kondisi yang WAJIB lolos sebelum prop dianggap siap cetak. Sisanya
# informatif: "miring 25 derajat" di luar toleransi detektor OpenCV,
# padahal pemindai HP sungguhan tinggal digeser sedikit oleh
# penggunanya. Menjadikannya syarat cuma bikin panik sia-sia.
KONDISI_WAJIB = ("asli", "diperkecil 50%", "buram (gaussian 5)",
                 "redup (60% kontras)", "derau kamera")


def kondisi_uji(arr):
    """Kondisi yang meniru pemindaian di dunia nyata, bukan di layar."""
    h, w = arr.shape[:2]
    return [
        ("asli", arr),
        ("diperkecil 50%", cv2.resize(arr, (w // 2, h // 2))),
        ("diperkecil 30%", cv2.resize(arr, (int(w * .3), int(h * .3)))),
        ("buram (gaussian 5)", cv2.GaussianBlur(arr, (5, 5), 0)),
        ("buram (gaussian 9)", cv2.GaussianBlur(arr, (9, 9), 0)),
        ("miring 10 derajat", _rotate(arr, 10)),
        ("miring 25 derajat", _rotate(arr, 25)),
        ("redup (60% kontras)", cv2.convertScaleAbs(arr, alpha=0.6, beta=40)),
        ("derau kamera", cv2.add(arr, np.random.normal(
            0, 12, arr.shape).astype(np.int8), dtype=cv2.CV_8U)),
    ]


def verifikasi(path, payload):
    """Kembalikan (lolos, total, gagal_wajib, gagal_opsional)."""
    arr = cv2.imread(path)
    kondisi = kondisi_uji(arr)
    gagal = [nama for nama, varian in kondisi
             if not _decode(varian, payload)]
    wajib = [g for g in gagal if g in KONDISI_WAJIB]
    opsional = [g for g in gagal if g not in KONDISI_WAJIB]
    return len(kondisi) - len(gagal), len(kondisi), wajib, opsional


def calibrate():
    """Sapu kombinasi koreksi galat x ukuran modul, ukur keterbacaannya.

    Dijalankan lewat `python scripts/make_qr.py --calibrate`. Ada di sini
    supaya angka ERROR_CORRECTION dan BOX_SIZE di atas bisa ditelusuri
    ulang, bukan diwariskan sebagai tebakan yang kebetulan jalan.
    """
    tingkat = {
        "L": qrcode.constants.ERROR_CORRECT_L,
        "M": qrcode.constants.ERROR_CORRECT_M,
        "Q": qrcode.constants.ERROR_CORRECT_Q,
        "H": qrcode.constants.ERROR_CORRECT_H,
    }
    contoh = [p for _, p, _, _ in build_scenarios()]
    np.random.seed(3)

    print("Kalibrasi parameter cetak QR")
    print("-" * 68)
    print(f"  {'EC':>3}{'box':>5}{'versi':>7}{'modul':>7}{'terbaca':>10}")
    hasil = []
    for ec, konst in tingkat.items():
        for box in (10, 12, 16, 20):
            lolos = jumlah = 0
            versi = modul = 0
            for payload in contoh:
                q = qrcode.QRCode(error_correction=konst, box_size=box,
                                  border=BORDER)
                q.add_data(payload)
                q.make(fit=True)
                img = q.make_image(fill_color="black",
                                   back_color="white").convert("RGB")
                arr = np.array(img)[:, :, ::-1].copy()
                versi, modul = q.version, arr.shape[0] // box - 2 * BORDER
                for _, varian in kondisi_uji(arr):
                    lolos += bool(_decode(varian, payload))
                    jumlah += 1
            hasil.append((lolos / jumlah, ec, box, versi, modul))
            print(f"  {ec:>3}{box:>5}{versi:>7}{modul:>7}"
                  f"{lolos:>6}/{jumlah:<4}")

    hasil.sort(reverse=True)
    skor, ec, box, versi, modul = hasil[0]
    print()
    print(f"  Terbaik: EC={ec} box={box} (versi {versi}, {modul}x{modul} modul, "
          f"{100 * skor:.0f}% terbaca)")
    print(f"  Terpakai sekarang: EC=Q box={BOX_SIZE}")


def main(lat=None, lng=None, out="props", caption=True):
    if lat is not None:
        seed.WARUNG["lat"], seed.WARUNG["lng"] = lat, lng
    os.makedirs(out, exist_ok=True)

    print(f"Jangkar warung : {seed.WARUNG['lat']:.6f}, {seed.WARUNG['lng']:.6f}")
    print(f"Folder keluaran: {os.path.abspath(out)}")
    print()

    total_gagal = 0
    for nama, payload, judul, subjudul in build_scenarios():
        path = os.path.join(out, f"{nama}.png")
        render(payload, judul, subjudul, caption).save(path, dpi=(300, 300))
        lolos, total, wajib, opsional = verifikasi(path, payload)

        print(f"  [{'GAGAL' if wajib else 'SIAP '}] {nama}.png — {judul}")
        print(f"          {lolos}/{total} kondisi terbaca, "
              f"{len(KONDISI_WAJIB) - len(wajib)}/{len(KONDISI_WAJIB)} wajib")
        if wajib:
            total_gagal += 1
            print(f"          GAGAL pada kondisi wajib: {', '.join(wajib)}")
        if opsional:
            print(f"          (di luar syarat: {', '.join(opsional)})")
        print(f"          {payload[:58]}...")
        print()

    print("-" * 68)
    if total_gagal:
        print(f"{total_gagal} berkas GAGAL di kondisi wajib — jangan dicetak")
        print("sebelum diperbaiki. Coba naikkan BOX_SIZE, atau jalankan")
        print("`python scripts/make_qr.py --calibrate` untuk menyapu ulang.")
    else:
        print("Semua prop lolos seluruh kondisi wajib. Siap cetak.")
    print()
    print("Cetak 300 dpi, minimal 3 cm sisi. Quiet zone putih di sekeliling")
    print("adalah bagian dari kode — jangan dipotong saat memotong stiker.")
    print("Cetak rangkap: satu set terpasang, satu set cadangan di tas.")
    return total_gagal


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--calibrate" in argv:
        calibrate()
        sys.exit(0)
    caption = "--no-caption" not in argv
    out = "props"
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    koordinat = [a for a in argv if not a.startswith("--")
                 and a != out]
    try:
        koordinat = [float(a) for a in koordinat]
    except ValueError:
        koordinat = []
    if len(koordinat) >= 2:
        main(koordinat[0], koordinat[1], out, caption)
    else:
        main(out=out, caption=caption)
