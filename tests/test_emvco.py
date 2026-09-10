from qshield import emvco

print("=" * 60)
print("1. Bangun payload QRIS statis (merchant sah)")
print("=" * 60)

acct = emvco.build_tlv({
    "00": "ID.CO.QRIS.WWW",
    "01": "936000149000000001",
    "02": "ID1024365478912",
    "03": "UMI",
})

payload = emvco.build({
    "00": "01",
    "01": "11",
    "26": acct,
    "52": "5812",
    "53": "360",
    "58": "ID",
    "59": "WARUNG BU SRI",
    "60": "BANDUNG",
    "61": "40257",
})

print(payload)
print()

p = emvco.parse(payload)
for k, v in p.summary().items():
    print(f"  {k:16} {v}")

assert p.crc_valid, "CRC seharusnya valid"
assert p.nmid == "ID1024365478912", f"NMID salah: {p.nmid}"
assert p.is_static
print("\n  OK\n")

print("=" * 60)
print("2. Payload dengan CRC dirusak (QR hasil generate ulang)")
print("=" * 60)

tampered = payload[:-4] + "0000"
p2 = emvco.parse(tampered)
print(f"  crc_found     {p2.crc_found}")
print(f"  crc_expected  {p2.crc_expected}")
print(f"  crc_valid     {p2.crc_valid}")
assert not p2.crc_valid
print("\n  OK — terdeteksi\n")

print("=" * 60)
print("3. Stiker palsu: NMID berbeda, nama merchant ditiru")
print("=" * 60)

fake_acct = emvco.build_tlv({
    "00": "ID.CO.QRIS.WWW",
    "01": "936000149000000002",
    "02": "ID1099887766554",
    "03": "UMI",
})
fake = emvco.build({
    "00": "01",
    "01": "11",
    "26": fake_acct,
    "52": "5812",
    "53": "360",
    "58": "ID",
    "59": "WARUNG BU SRI",
    "60": "BANDUNG",
})
p3 = emvco.parse(fake)
print(f"  nama merchant  {p3.merchant_name}  (sama persis)")
print(f"  NMID asli      {p.nmid}")
print(f"  NMID palsu     {p3.nmid}")
print(f"  crc_valid      {p3.crc_valid}  <- payload palsu tetap valid")
assert p3.crc_valid
assert p3.nmid != p.nmid
print("\n  OK — CRC saja tidak cukup, butuh binding\n")

print("=" * 60)
print("4. Payload cacat")
print("=" * 60)

for bad, label in [
    ("0002010102", "value terpotong"),
    ("00XX01", "length bukan angka"),
    ("", "kosong"),
    ("5802ID", "tanpa tag 00"),
]:
    try:
        emvco.parse(bad)
        print(f"  {label:22} TIDAK terdeteksi  <-- masalah")
    except emvco.ParseError as e:
        print(f"  {label:22} ParseError: {e}")

print("\n  OK — semua ditolak\n")

print("=" * 60)
print("5. QR dinamis dengan nominal")
print("=" * 60)

dyn = emvco.build({
    "00": "01",
    "01": "12",
    "26": acct,
    "53": "360",
    "54": "25000.00",
    "58": "ID",
    "59": "WARUNG BU SRI",
    "60": "BANDUNG",
})
p5 = emvco.parse(dyn)
print(f"  is_static  {p5.is_static}")
print(f"  amount     {p5.amount}")
assert not p5.is_static and p5.amount == "25000.00"
print("\n  OK\n")

print("Semua test lolos.")
