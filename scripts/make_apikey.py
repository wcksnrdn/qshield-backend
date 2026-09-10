"""
Bikin kunci API baru untuk satu PJP.

    python scripts/make_apikey.py pjp-alpha

Mencetak dua hal: kunci mentah yang diberikan ke PJP (sekali saja, tidak
bisa dipulihkan), dan baris env berisi hash-nya untuk sisi server.

Kunci mentah tidak pernah disimpan di mana pun oleh Q-Shield. Kalau
hilang, terbitkan yang baru — jangan mencoba memulihkan yang lama.
"""

import sys

from qshield import auth


def main(client_id: str) -> int:
    if not client_id or not client_id.replace("-", "").replace("_", "").isalnum():
        print("client_id hanya boleh huruf, angka, '-' dan '_'", file=sys.stderr)
        return 2

    mentah = auth.new_key()
    digest = auth.hash_key(mentah)

    print("=" * 68)
    print(f"Kunci API untuk: {client_id}")
    print("=" * 68)
    print()
    print("  BERIKAN INI KE PJP (muncul sekali, tidak bisa dipulihkan):")
    print()
    print(f"    {mentah}")
    print()
    print("  PASANG INI DI SERVER:")
    print()
    print(f"    export QSHIELD_API_KEYS=\"{client_id}:{digest}\"")
    print()
    print("  Sudah ada klien lain? Gabungkan dengan koma:")
    print(f"    export QSHIELD_API_KEYS=\"pjp-lama:<hash>,{client_id}:{digest}\"")
    print()
    print("  Dipakai klien sebagai header:")
    print(f"    {auth.API_KEY_HEADER}: {mentah}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
