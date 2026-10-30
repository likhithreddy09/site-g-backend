import os

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB = os.getenv("MONGO_DB", "siteguard")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
    JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "168"))

    PUBLIC_API_URL = os.getenv("PUBLIC_API_URL", "http://localhost:5050").rstrip("/")
    APP_URL = os.getenv("APP_URL", "http://localhost:3100").rstrip("/")
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3100").split(",") if o.strip()]

    # Never enable in production: lets monitors reach localhost / private networks.
    ALLOW_PRIVATE_TARGETS = _bool("ALLOW_PRIVATE_TARGETS", False)

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "Watchfront <alerts@watchfront.in>")
    SMTP_TLS = _bool("SMTP_TLS", True)
    # Implicit SSL (SMTP_SSL). Default on for port 465 — preferred for GoDaddy from cloud hosts.
    SMTP_SSL = _bool("SMTP_SSL", str(os.getenv("SMTP_PORT", "465")).strip() == "465")
    SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "45"))
    SMTP_RETRIES = int(os.getenv("SMTP_RETRIES", "3"))

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")

    EMBED_WORKER = _bool("EMBED_WORKER", True)
    HTTP_WORKERS = int(os.getenv("HTTP_WORKERS", "16"))
    BROWSER_WORKERS = int(os.getenv("BROWSER_WORKERS", "2"))
    DISPATCH_INTERVAL_SEC = int(os.getenv("DISPATCH_INTERVAL_SEC", "5"))

    STORAGE_DIR = os.getenv("STORAGE_DIR", os.path.join(BASE_DIR, "storage"))

    # Dodo Payments (never commit real keys — set via env / Railway)
    # Docs: https://docs.dodopayments.com/developer-resources/checkout-session
    DODO_PAYMENTS_API_KEY = os.getenv("DODO_PAYMENTS_API_KEY", "").strip()
    DODO_PAYMENTS_WEBHOOK_KEY = os.getenv("DODO_PAYMENTS_WEBHOOK_KEY", "").strip()
    # test_mode | live_mode
    DODO_PAYMENTS_ENV = os.getenv("DODO_PAYMENTS_ENV", "test_mode").strip().lower()
    DODO_PRODUCT_STARTER = os.getenv("DODO_PRODUCT_STARTER", "").strip()
    DODO_PRODUCT_AGENCY = os.getenv("DODO_PRODUCT_AGENCY", "").strip()
    DODO_PRODUCT_AGENCY_PRO = os.getenv("DODO_PRODUCT_AGENCY_PRO", "").strip()

    # Ops gate for /check-active-user (override in env for production)
    OPS_PIN = os.getenv("OPS_PIN", "852093").strip()
    OPS_BIRTH_CITY = os.getenv("OPS_BIRTH_CITY", "usa").strip().lower()
    # Users with last_seen_at within this window count as "live"
    OPS_LIVE_MINUTES = int(os.getenv("OPS_LIVE_MINUTES", "15"))
