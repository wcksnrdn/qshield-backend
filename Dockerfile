# Q-Shield — image produksi.
#
# Catatan: untuk demo 3 Oktober, JANGAN pakai ini. Jalankan uvicorn
# langsung di laptop. Container menambah satu lapis yang bisa gagal
# pagi hari-H tanpa memberi keuntungan di panggung. Lihat DEPLOY.md §4.

FROM python:3.12-slim AS base

# Tidak menulis .pyc, tidak buffer stdout supaya audit log langsung
# terlihat di `docker logs` alih-alih tertahan.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependensi disalin lebih dulu supaya lapisannya ter-cache dan tidak
# ikut dibangun ulang setiap kali kode berubah.
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

COPY scripts/ ./scripts/

# Proses yang tidak butuh root tidak boleh punya root.
RUN useradd --create-home --shell /usr/sbin/nologin qshield \
    && mkdir -p /data \
    && chown -R qshield:qshield /app /data
USER qshield

# Basis data hidup di volume, bukan di lapisan image, supaya tidak
# hilang saat image diperbarui.
ENV QSHIELD_DB=/data/qshield.db
VOLUME ["/data"]

EXPOSE 8000

# Tidak ada secret yang dipanggang ke dalam image. QSHIELD_API_KEYS dan
# QSHIELD_DEVICE_SALT disodorkan saat run — image boleh dibagikan,
# konfigurasinya tidak.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status==200 else 1)"

# Tanpa --reload: itu untuk pengembangan.
CMD ["uvicorn", "qshield.api:app", "--host", "0.0.0.0", "--port", "8000"]
