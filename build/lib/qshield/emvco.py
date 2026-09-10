"""
Parser payload QRIS (EMVCo Merchant Presented Mode).

Payload QRIS adalah rangkaian TLV: setiap field terdiri dari
tag 2 digit, panjang 2 digit, lalu value sepanjang itu.
Beberapa field adalah template yang isinya TLV lagi (nested).

Referensi tag yang dipakai:
  00  Payload format indicator
  01  Point of initiation: "11" statis, "12" dinamis
  26-51 Merchant account information (template, nested)
  52  Merchant category code
  53  Currency (360 = IDR)
  54  Transaction amount (hanya pada QR dinamis)
  58  Country code
  59  Merchant name
  60  Merchant city
  61  Postal code
  62  Additional data (template)
  63  CRC16
"""

from dataclasses import dataclass, field
from typing import Optional

QRIS_GUIDS = ("ID.CO.QRIS.WWW", "ID.CO.QRIS")

MERCHANT_TEMPLATE_TAGS = [f"{i:02d}" for i in range(26, 52)]

NESTED_TAGS = set(MERCHANT_TEMPLATE_TAGS) | {"62", "64"}

MERCHANT_CRITERIA = {
    "UMI": "Usaha Mikro",
    "UKE": "Usaha Kecil",
    "UME": "Usaha Menengah",
    "UBE": "Usaha Besar",
    "URE": "Usaha Regular",
}


class ParseError(Exception):
    """Payload tidak sesuai struktur TLV EMVCo."""


@dataclass
class MerchantAccount:
    """Satu template merchant account (tag 26-51).

    Struktur sub-tag pada QRIS:
      00  GUID, mis. ID.CO.QRIS.WWW
      01  Merchant PAN (nomor kartu virtual, diawali kode PJP)
      02  NMID / National Merchant ID, diawali "ID"
      03  Kriteria usaha (UMI/UKE/UME/UBE)
    """

    tag: str
    guid: Optional[str] = None
    pan: Optional[str] = None
    nmid: Optional[str] = None
    criteria: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def is_qris(self) -> bool:
        return bool(self.guid and self.guid.upper().startswith("ID.CO.QRIS"))

    @property
    def issuer_code(self) -> Optional[str]:
        """4 digit awal PAN menandakan PJP penerbit."""
        if self.pan and len(self.pan) >= 8:
            return self.pan[4:8]
        return None


@dataclass
class QrisPayload:
    raw: str
    tags: dict
    accounts: list
    crc_valid: bool
    crc_found: Optional[str] = None
    crc_expected: Optional[str] = None

    @property
    def is_static(self) -> bool:
        return self.tags.get("01", "11") == "11"

    @property
    def merchant_name(self) -> Optional[str]:
        return self.tags.get("59")

    @property
    def merchant_city(self) -> Optional[str]:
        return self.tags.get("60")

    @property
    def postal_code(self) -> Optional[str]:
        return self.tags.get("61")

    @property
    def mcc(self) -> Optional[str]:
        return self.tags.get("52")

    @property
    def currency(self) -> Optional[str]:
        return self.tags.get("53")

    @property
    def amount(self) -> Optional[str]:
        return self.tags.get("54")

    @property
    def country(self) -> Optional[str]:
        return self.tags.get("58")

    @property
    def primary_account(self) -> Optional[MerchantAccount]:
        for acc in self.accounts:
            if acc.is_qris and acc.nmid:
                return acc
        for acc in self.accounts:
            if acc.nmid:
                return acc
        return self.accounts[0] if self.accounts else None

    @property
    def nmid(self) -> Optional[str]:
        acc = self.primary_account
        return acc.nmid if acc else None

    @property
    def criteria_label(self) -> Optional[str]:
        acc = self.primary_account
        if acc and acc.criteria:
            return MERCHANT_CRITERIA.get(acc.criteria, acc.criteria)
        return None

    def summary(self) -> dict:
        return {
            "nmid": self.nmid,
            "merchant_name": self.merchant_name,
            "merchant_city": self.merchant_city,
            "postal_code": self.postal_code,
            "mcc": self.mcc,
            "criteria": self.criteria_label,
            "is_static": self.is_static,
            "amount": self.amount,
            "currency": self.currency,
            "country": self.country,
            "crc_valid": self.crc_valid,
        }


def crc16_ccitt(data: str) -> str:
    """CRC16/CCITT-FALSE: poly 0x1021, init 0xFFFF, tanpa refleksi."""
    crc = 0xFFFF
    for ch in data.encode("utf-8"):
        crc ^= ch << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def parse_tlv(data: str) -> dict:
    """Pecah string TLV jadi dict {tag: value}. Tidak rekursif."""
    result = {}
    i = 0
    n = len(data)
    while i < n:
        if i + 4 > n:
            raise ParseError(f"TLV terpotong pada posisi {i}")
        tag = data[i:i + 2]
        length_str = data[i + 2:i + 4]
        if not tag.isdigit() or not length_str.isdigit():
            raise ParseError(f"Tag/length bukan angka pada posisi {i}")
        length = int(length_str)
        start = i + 4
        end = start + length
        if end > n:
            raise ParseError(
                f"Value tag {tag} melebihi panjang payload "
                f"(butuh {length}, tersisa {n - start})"
            )
        result[tag] = data[start:end]
        i = end
    return result


def _parse_merchant_account(tag: str, value: str) -> MerchantAccount:
    try:
        sub = parse_tlv(value)
    except ParseError:
        return MerchantAccount(tag=tag, raw={"00": value})
    return MerchantAccount(
        tag=tag,
        guid=sub.get("00"),
        pan=sub.get("01"),
        nmid=sub.get("02"),
        criteria=sub.get("03"),
        raw=sub,
    )


def parse(payload: str) -> QrisPayload:
    """Parse payload QRIS lengkap beserta validasi CRC16."""
    payload = payload.strip()
    if not payload:
        raise ParseError("Payload kosong")

    tags = parse_tlv(payload)

    if "00" not in tags:
        raise ParseError("Tag 00 (payload format indicator) tidak ditemukan")

    crc_found = tags.get("63")
    crc_valid = False
    crc_expected = None
    idx = payload.rfind("6304")
    if crc_found and idx != -1:
        crc_expected = crc16_ccitt(payload[:idx + 4])
        crc_valid = crc_found.upper() == crc_expected

    accounts = [
        _parse_merchant_account(t, tags[t])
        for t in MERCHANT_TEMPLATE_TAGS
        if t in tags
    ]

    return QrisPayload(
        raw=payload,
        tags=tags,
        accounts=accounts,
        crc_valid=crc_valid,
        crc_found=crc_found,
        crc_expected=crc_expected,
    )


def build(fields: dict) -> str:
    """Susun payload QRIS dari dict {tag: value}, CRC dihitung otomatis.

    Dipakai untuk membuat data uji dan QR skenario demo.
    """
    parts = []
    for tag in sorted(fields.keys()):
        if tag == "63":
            continue
        value = fields[tag]
        parts.append(f"{tag}{len(value):02d}{value}")
    body = "".join(parts) + "6304"
    return body + crc16_ccitt(body)


def build_tlv(fields: dict) -> str:
    """Susun sub-TLV (untuk isi template merchant account)."""
    return "".join(f"{t}{len(v):02d}{v}" for t, v in sorted(fields.items()))
