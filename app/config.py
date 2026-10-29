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
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "Watchfront <alerts@watchfront.in>")
    SMTP_TLS = _bool("SMTP_TLS", True)

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")

    EMBED_WORKER = _bool("EMBED_WORKER", True)
    HTTP_WORKERS = int(os.getenv("HTTP_WORKERS", "16"))
    BROWSER_WORKERS = int(os.getenv("BROWSER_WORKERS", "2"))
    DISPATCH_INTERVAL_SEC = int(os.getenv("DISPATCH_INTERVAL_SEC", "5"))

    STORAGE_DIR = os.getenv("STORAGE_DIR", os.path.join(BASE_DIR, "storage"))

    # Cashfree PG (never commit real keys — set via env / Railway)
    # Docs: https://www.cashfree.com/docs/payments/online/web/redirect
    CASHFREE_APP_ID = os.getenv("CASHFREE_APP_ID", "").strip()
    CASHFREE_SECRET_KEY = os.getenv("CASHFREE_SECRET_KEY", "").strip()
    CASHFREE_ENV = os.getenv("CASHFREE_ENV", "production").strip().lower()  # sandbox | production
    CASHFREE_API_VERSION = os.getenv("CASHFREE_API_VERSION", "2023-08-01").strip()
    # Comma-separated: cc,dc,upi,nb,app,paylater,ccc,ppc,emi,... — blank = all account methods
    CASHFREE_PAYMENT_METHODS = os.getenv("CASHFREE_PAYMENT_METHODS", "cc,dc,upi,nb,app,paylater").strip()
