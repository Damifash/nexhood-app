# NEXHOOD BACKEND BUILD MARKER: v32-2026-10-13-estate-bills-mobile
# If /health below doesn't return this exact build string, the running
# process is NOT this file — kill whatever's on port 8000 and restart.
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, UploadFile, File, Body, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from pymongo import MongoClient
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import re
import html  # escaping user text in outgoing emails
import qrcode
import pyotp
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import asyncio, socketio
import logging
import base64
from io import BytesIO
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import csv
from io import StringIO
from dotenv import load_dotenv
from collections import defaultdict
import resend  # Transactional email
import secrets  # Password reset tokens
import json
# For push notifications (install firebase-admin)
# import firebase_admin
# from firebase_admin import credentials, messaging


class MongoJSONEncoder(json.JSONEncoder):
    """Handles MongoDB ObjectId and datetime serialization."""
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def to_utc_iso(value: datetime) -> str:
    """All datetimes in this app are stored as naive UTC. Sending them
    without a timezone made browsers treat them as local time (every time
    in the app showed 1 hour early in Nigeria), and the 6-digit
    microseconds made some browsers (Safari) show "Invalid Date". Always
    send e.g. 2026-10-12T15:56:09.633Z instead."""
    if value.tzinfo is not None:
        value = (value - value.utcoffset()).replace(tzinfo=None)
    return value.isoformat(timespec="milliseconds") + "Z"


def serialize_doc(doc) -> dict:
    """Recursively convert a MongoDB document to be JSON-safe.

    NOTE: any dict key literally named "_id" gets renamed to "id" here,
    including keys produced by aggregation $group stages (e.g. a date
    string or an incident type used as the group key) — not just real
    Mongo ObjectIds. That's intentional and the frontend is written to
    expect it, so don't "fix" this without also updating the client.
    """
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if not isinstance(doc, dict):
        return doc
    result = {}
    for key, value in doc.items():
        if key == "_id":
            result["id"] = str(value)
        elif isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = to_utc_iso(value)
        elif isinstance(value, list):
            result[key] = [serialize_doc(v) if isinstance(v, (dict, list)) else str(v) if isinstance(v, ObjectId) else v for v in value]
        elif isinstance(value, dict):
            result[key] = serialize_doc(value)
        else:
            result[key] = value
    return result


load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
# The interactive API docs (/docs, /redoc, /openapi.json) are hidden in
# production — they were publicly listing every endpoint. Set ENABLE_DOCS=1
# locally if you want them back while developing.
_docs_on = os.getenv("ENABLE_DOCS") == "1"
app = FastAPI(
    title="NexHood Backend",
    description="Backend for estate security management",
    docs_url="/docs" if _docs_on else None,
    redoc_url="/redoc" if _docs_on else None,
    openapi_url="/openapi.json" if _docs_on else None,
)

# Initialize Socket.IO
# This was set to an empty list, which blocks every origin — real-time
# alerts/community updates over the socket.io connection would have been
# silently broken in production even though the REST API worked fine.
# Kept in sync with the CORSMiddleware origins above.
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://nexhoodapp.com",
        "https://www.nexhoodapp.com",
    ]
)

# CORS Middleware — locked to real domains now that we're deploying.
# allow_credentials=True + a literal "*" origin is actually invalid per the
# CORS spec (browsers reject it), so that wildcard had to go anyway. The
# regex covers Vercel's preview-deployment URLs (each PR/branch gets its
# own random *.vercel.app subdomain) without listing them one by one.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://nexhoodapp.com",
        "https://www.nexhoodapp.com",
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Session Middleware
app.add_middleware(SessionMiddleware, secret_key=os.getenv("JWT_SECRET", "your-secret-key"))

# Environment Variables
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/security-app")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
if JWT_SECRET == "your-secret-key":
    # Every login/reset/socket-auth token on the entire app is signed with
    # this value. If the JWT_SECRET env var is ever missing on Render, the
    # app doesn't fail to start — it silently signs every token with this
    # well-known placeholder instead, which means anyone could forge a
    # valid token for any account, including an admin's. This can't safely
    # be a hard crash (a typo here would take the whole app down instead of
    # just warning), so it's a loud startup log instead — if you ever see
    # this line in Render's logs, JWT_SECRET is not set and needs fixing
    # immediately.
    logger.error(
        "SECURITY WARNING: JWT_SECRET environment variable is not set. "
        "Falling back to an insecure default — tokens can be forged. "
        "Set JWT_SECRET in your hosting environment now."
    )
ALGORITHM = "HS256"
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "Nexhood <notifications@nexhoodapp.com>")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
LOGIN_URL = f"{FRONTEND_URL}/login"
POLICE_EMAIL = os.getenv("POLICE_EMAIL")  # fallback; admins can set per-estate in Settings
# Where "Contact us" submissions on the landing page get emailed. Defaults to
# the real inbox so this works out of the box even if the env var is never set.
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "fasoro@nexhoodapp.com")
# Served as a static asset from the frontend (nexhood-web/public/brand/), so
# this only resolves once FRONTEND_URL points at the real deployed site —
# on localhost it just won't load, which is fine for local dev.
LOGO_URL = f"{FRONTEND_URL}/brand/nexhood-mark-email.png"

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY
    logger.info("Resend email client configured")
else:
    logger.info("RESEND_API_KEY not set — email notifications disabled")

# Termii SMS was removed for now (email-only, per cost/simplicity call) —
# every notification below goes through send_email(). If SMS comes back
# later, this is the one function to reintroduce and re-wire.


def send_email(to: Optional[str], subject: str, html: str) -> None:
    """Best-effort transactional email via Resend. Never raises — a failed
    or unconfigured email must not block the request that triggered it."""
    if not RESEND_API_KEY or not to:
        logger.info(f"Email skipped (Resend not configured or no recipient): {subject}")
        return
    try:
        resend.Emails.send({
            "from": RESEND_FROM_EMAIL,
            "to": [to],
            "subject": subject,
            "html": html,
        })
        logger.info(f"Email sent to {to}: {subject}")
    except Exception as e:
        logger.error(f"Resend email failed for {to}: {e}")


def notify_by_email(recipients, subject: str, html: str) -> None:
    """Send the same notification to several people, one by one, never
    raising. Designed to run as a FastAPI background task so the request
    that triggered it (a panic alert, an incident) responds instantly
    instead of waiting for every email round-trip. Recipients are
    de-duplicated and capped at 95 to stay inside Resend's free tier
    daily limit even in the worst case."""
    seen = set()
    clean = []
    for r in recipients:
        if r and r not in seen:
            seen.add(r)
            clean.append(r)
    if len(clean) > 95:
        logger.warning(f"notify_by_email: capping {len(clean)} recipients to 95 for '{subject}'")
        clean = clean[:95]
    for email_addr in clean:
        send_email(email_addr, subject, html)


def branded_email(title: str, body_html: str) -> str:
    """Wraps every outgoing email in one consistent NexHood-branded shell —
    invites, welcomes, alerts, police notifications, and password resets all
    used to be bare unstyled paragraphs with no shared identity. Pass a short
    title and the inner body HTML; this handles the header/footer chrome.

    The logo is an <img> pointing at LOGO_URL (a static asset on the
    deployed frontend) with the "NexHood" text right next to it — most
    email clients block remote images by default until the recipient clicks
    "show images," so the text can't depend on the image loading. If it
    doesn't load, the header still reads correctly as plain text."""
    return f"""
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f5f7;padding:32px 16px;">
      <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #e5e7eb;">
        <div style="background:#1e2a5e;padding:18px 28px;display:flex;align-items:center;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
            <td style="vertical-align:middle;padding-right:10px;">
              <img src="{LOGO_URL}" width="26" height="26" alt="" style="display:block;border-radius:6px;" />
            </td>
            <td style="vertical-align:middle;">
              <span style="color:#ffffff;font-size:18px;font-weight:700;letter-spacing:0.3px;">NexHood</span>
            </td>
          </tr></table>
        </div>
        <div style="padding:28px;">
          <h2 style="margin:0 0 16px;color:#111827;font-size:18px;">{title}</h2>
          <div style="color:#374151;font-size:14px;line-height:1.6;">{body_html}</div>
        </div>
        <div style="padding:16px 28px;background:#f9fafb;border-top:1px solid #f0f0f0;">
          <p style="margin:0;color:#9ca3af;font-size:12px;">Estate security, made simple. Sent by NexHood — if this wasn't you, you can safely ignore this email.</p>
        </div>
      </div>
    </div>
    """


def normalize_phone(raw: str) -> str:
    """Accepts the way Nigerians actually type phone numbers — 08032292627,
    8032292627, 2348032292627, or +2348032292627 — and returns E.164
    (+234...). Previously the API only accepted a leading '+', so anyone
    typing their number the normal local way (0803...) got rejected at
    signup with no explanation. Falls back to a generic international check
    for non-Nigerian numbers so this doesn't break other countries."""
    digits = re.sub(r"[^\d+]", "", raw or "")
    if not digits:
        raise ValueError("Phone number is required")
    # People often keep the leading 0 after the country code
    # (+2340803..., 2340803...). That 0 must go, or the number is invalid.
    if re.fullmatch(r"\+?2340\d{10}", digits):
        digits = "+234" + digits[-10:]
    if digits.startswith("+"):
        candidate = digits
    elif digits.startswith("234") and len(digits) >= 12:
        candidate = "+" + digits
    elif digits.startswith("0") and len(digits) == 11:
        candidate = "+234" + digits[1:]
    elif len(digits) == 10:
        # Typed without the leading 0, e.g. "8032292627"
        candidate = "+234" + digits
    else:
        candidate = "+" + digits
    if not re.fullmatch(r"\+[1-9]\d{6,14}", candidate):
        raise ValueError("Enter a valid phone number, e.g. 08012345678")
    return candidate


def normalize_email(raw: str) -> str:
    """Emails are case-insensitive by spec, but this app was storing and
    matching them as-typed — meaning Fasoro@x.com and fasoro@x.com were
    treated as two different accounts, and a user who registered with caps
    could get "incorrect password" trying to log in with lowercase (or vice
    versa). New/updated accounts are stored lowercase from here on."""
    return (raw or "").strip().lower()


def email_query(raw: str) -> dict:
    """Case-insensitive, whitespace-safe exact-match query for looking up
    an email that predates the normalize_email() fix above — some accounts
    still have mixed-case emails stored from before this change, so lookups
    stay case-insensitive even though new writes are lowercase."""
    return {"email": {"$regex": f"^{re.escape((raw or '').strip())}$", "$options": "i"}}

# Firebase placeholder
# cred = credentials.Certificate("path/to/firebase.json")
# firebase_admin.initialize_app(cred)

# MongoDB Setup
try:
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    db = client["nexhood"]
    users_collection = db["users"]
    estates_collection = db["estates"]
    passes_collection = db["visitor_passes"]
    incidents_collection = db["incidents"]
    alerts_collection = db["alerts"]
    audit_logs_collection = db["audit_logs"]
    posts_collection = db["posts"]
    donations_collection = db["donations"]
    campaigns_collection = db["welfare_campaigns"]
    contact_messages_collection = db["contact_messages"]
    waitlist_collection = db["waitlist"]
    login_logs_collection = db["login_logs"]
    client.server_info()
    logger.info("Connected to MongoDB")
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    raise

# Geo index for locations
incidents_collection.create_index([("location", "2dsphere")])
alerts_collection.create_index([("location", "2dsphere")])
# Waitlist lookups: duplicate check by phone, referral lookup by code, and
# "how many people from this estate" counts. Wrapped so a index hiccup can
# never stop the API from booting for existing users.
try:
    waitlist_collection.create_index("phone")
    waitlist_collection.create_index("ref_code")
    waitlist_collection.create_index("estate_key")
except Exception as e:
    logger.error(f"Waitlist index creation failed (non-fatal): {e}")

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Setup
security = HTTPBearer()

# Rate Limiting Store (in-memory for simplicity, use Redis in production)
alert_rate_limit = defaultdict(list)
# Login had no brute-force protection at all — unlimited password guesses
# against any email, forever. Keyed by the submitted email (not IP, since
# Render sits behind a proxy and most requests share edge IPs) so a
# credential-stuffing run against one account gets capped regardless of
# where it's coming from. In-memory like alert_rate_limit above — resets on
# deploy/restart, which is an acceptable tradeoff at this scale; a Redis-
# backed limiter would be the real fix if this ever needs to survive
# restarts or run across multiple server instances.
login_rate_limit = defaultdict(list)

# Forgot-password and the public contact form both trigger outbound email,
# so left unlimited they were a free lever for draining the Resend quota
# or bombing someone's inbox with reset emails. Same in-memory pattern.
reset_rate_limit = defaultdict(list)
contact_rate_limit = defaultdict(list)
waitlist_rate_limit = defaultdict(list)
register_rate_limit = defaultdict(list)
police_rate_limit = defaultdict(list)
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "30"))


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------
class BadgeAward(BaseModel):
    badge: str
    awarded_at: datetime = Field(default_factory=datetime.utcnow)


class UserCreate(BaseModel):
    name: str = Field(..., min_length=2)
    email: EmailStr
    # Accepts local Nigerian formats (08032292627) as well as E.164 — see
    # normalize_phone() below, which does the actual conversion/validation.
    phone: str = Field(...)
    password: str = Field(..., min_length=6)
    role: str = Field(..., pattern="^(resident|guard|admin|super_admin|police)$")
    estate_id: Optional[str] = None
    apartment: Optional[str] = None
    badges: List[BadgeAward] = []

    @field_validator("phone")
    @classmethod
    def _normalize_phone(cls, v):
        try:
            return normalize_phone(v)
        except ValueError as e:
            raise ValueError(str(e))


class UserResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    phone: str
    role: str
    # Both of these are frequently absent on freshly self-registered users
    # (apartment isn't collected on the public form; estate_id is only
    # sometimes pre-resolved before this model validates). In Pydantic v2,
    # `Optional[str]` alone still means REQUIRED-but-nullable — it does NOT
    # default to None the way it did in v1. Without an explicit `= None`
    # here, login 500s the instant it hits a user missing either key.
    estate_id: Optional[str] = None
    estate_name: Optional[str] = None
    apartment: Optional[str] = None
    is_active: bool
    last_seen: datetime
    created_at: datetime
    badges: List[BadgeAward]

    class Config:
        from_attributes = True


class EstateCreate(BaseModel):
    name: str = Field(..., min_length=2)
    address: str = Field(..., min_length=5)
    settings: Optional[Dict] = {
        "allowGuests": True,
        "requireApproval": False,
        "maxVisitorDuration": 24,
        "emergencyContacts": [],
        "operatingHours": {"start": "00:00", "end": "23:59"}
    }
    subscription: Optional[Dict] = {"plan": "starter", "status": "trial", "expiresAt": None}
    coordinates: Optional[Dict[str, float]] = None


class VisitorPassCreate(BaseModel):
    visitor_name: str = Field(..., min_length=2)
    visitor_phone: Optional[str] = None
    visitor_email: Optional[EmailStr] = None
    vehicle_details: Optional[Dict] = None
    purpose: Optional[str] = None
    valid_from: datetime
    valid_until: datetime
    entry_gate: Optional[str] = None


class VisitorPassValidate(BaseModel):
    # No longer required — a guard validating a code already knows which
    # gate they're standing at, so making them type/select it every single
    # validation was pure friction for no real benefit. Kept optional (not
    # removed) so a future multi-gate estate can still pass it through if
    # it's ever wired to a guard's assigned post.
    entry_gate: Optional[str] = None


class IncidentCreate(BaseModel):
    type: str = Field(..., pattern="^(emergency|theft|vandalism|dispute|suspicious_activity|maintenance|other)$")
    severity: str = Field("medium", pattern="^(low|medium|high|critical)$")
    title: str = Field(..., min_length=3, max_length=150)
    description: str = Field(..., min_length=10, max_length=5000)
    location: Optional[Dict] = None
    images: Optional[List[str]] = Field(None, max_length=4)

    @field_validator("images")
    @classmethod
    def _cap_images(cls, v):
        if v and sum(len(i) for i in v) > 6 * 1024 * 1024:
            raise ValueError("Photos are too large (max about 4MB in total)")
        return v


class UserInvite(BaseModel):
    name: str = Field(..., min_length=2)
    email: EmailStr
    phone: str = Field(...)
    role: str = Field("resident", pattern="^(resident|guard|admin|police)$")
    apartment: Optional[str] = None

    @field_validator("phone")
    @classmethod
    def _normalize_phone(cls, v):
        try:
            return normalize_phone(v)
        except ValueError as e:
            raise ValueError(str(e))


class ProfileUpdate(BaseModel):
    """Self-serve edits from Settings — deliberately a small allowlist
    (name, phone, email, apartment). Role/estate changes stay admin-only."""
    name: Optional[str] = Field(None, min_length=2)
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    apartment: Optional[str] = None

    @field_validator("phone")
    @classmethod
    def _normalize_phone(cls, v):
        if v is None or not v.strip():
            return None
        try:
            return normalize_phone(v)
        except ValueError as e:
            raise ValueError(str(e))


class EstateProfileUpdate(BaseModel):
    """Lets an estate admin rename their estate / fix its address from
    Settings, without touching the police-contact settings endpoint."""
    name: Optional[str] = Field(None, min_length=2)
    address: Optional[str] = Field(None, min_length=5)


class AlertCreate(BaseModel):
    type: str = Field(..., pattern="^(panic|emergency|security_breach|fire|medical|general)$")
    message: Optional[str] = None
    location: Optional[Dict] = None
    priority: str = Field("high", pattern="^(low|medium|high|critical)$")


class PoliceIntegration(BaseModel):
    alert_id: str = Field(..., min_length=1)


class PostCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)
    type: str = Field(..., pattern="^(event|appreciation|general)$")
    # Data URIs (e.g. "data:image/jpeg;base64,...") from /api/upload/image —
    # kept small in practice by the frontend's client-side size cap, since
    # these get embedded directly in the Mongo document, not object storage.
    images: Optional[List[str]] = Field(None, max_length=4)

    @field_validator("images")
    @classmethod
    def _cap_images(cls, v):
        # Images are stored inside the database document itself, and the
        # free database is 512MB for every estate combined. Cap total size.
        if v and sum(len(i) for i in v) > 6 * 1024 * 1024:
            raise ValueError("Images are too large (max about 4MB in total)")
        return v


class DonationCreate(BaseModel):
    amount: float = Field(..., gt=0)
    for_role: str = Field(..., pattern="^(guards|police)$")
    campaign_id: Optional[str] = None


class WelfareCampaignCreate(BaseModel):
    title: str = Field(..., min_length=3)
    description: Optional[str] = None
    for_role: str = Field(..., pattern="^(guards|police|general)$")
    goal_amount: Optional[float] = Field(None, gt=0)


class ConfigCreate(BaseModel):
    estate_id: str
    notification_roles: List[str] = Field(default=["admin"], pattern="^(resident|guard|admin|super_admin)$")
    max_notifications: int = Field(default=5, ge=1)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6)


class ContactMessageCreate(BaseModel):
    """The landing page 'Contact us' form — deliberately public, no auth,
    since the whole point is reaching people who don't have an account yet."""
    name: str = Field(..., min_length=2)
    email: EmailStr
    message: str = Field(..., min_length=10, max_length=3000)


WAITLIST_ROLES = ("resident", "estate_admin", "security", "other")
WAITLIST_SIZES = ("under_50", "50_200", "200_plus")


class WaitlistCreate(BaseModel):
    """Public landing-page waitlist. No auth — the people signing up don't
    have accounts yet. `website` is a honeypot (real users never see it) and
    `elapsed_ms` is how long the form was open; both are cheap bot filters."""
    name: str = Field(..., min_length=2, max_length=80)
    phone: str = Field(...)
    email: Optional[EmailStr] = None
    role: str = Field(...)
    estate_name: str = Field(..., min_length=2, max_length=100)
    area: str = Field(..., min_length=2, max_length=60)
    estate_size: Optional[str] = None
    source: Optional[str] = Field(None, max_length=300)
    ref: Optional[str] = Field(None, max_length=20)
    website: Optional[str] = None
    elapsed_ms: Optional[int] = None

    @field_validator("phone")
    @classmethod
    def _normalize_phone(cls, v):
        return normalize_phone(v)

    @field_validator("role")
    @classmethod
    def _check_role(cls, v):
        if v not in WAITLIST_ROLES:
            raise ValueError("Pick a role")
        return v

    @field_validator("estate_size")
    @classmethod
    def _check_size(cls, v):
        if v in (None, ""):
            return None
        if v not in WAITLIST_SIZES:
            raise ValueError("Pick an estate size")
        return v

    @field_validator("name", "estate_name", "area")
    @classmethod
    def _strip(cls, v):
        v = re.sub(r"\s+", " ", (v or "")).strip()
        if len(v) < 2:
            raise ValueError("This field is required")
        return v


class SyncAction(BaseModel):
    id: str
    type: str = Field(..., pattern="^(validate_visitor|create_incident|create_alert)$")
    data: Dict
    timestamp: datetime


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
# Chosen to avoid characters that get misread when spoken aloud at a gate
# or typed on a phone — no 0/O, 1/I/L confusion.
VISITOR_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def generate_visitor_code() -> str:
    """Short 4-character visitor pass code. Deliberately NOT the same
    generator as temp passwords below — this one is short on purpose for
    quick gate entry, that one needs to stay a real credential."""
    return "".join(secrets.choice(VISITOR_CODE_ALPHABET) for _ in range(4))


def generate_temp_password() -> str:
    """Temp password issued via invite — this logs someone into a real
    account, so it stays longer/stronger than the visitor code."""
    return pyotp.random_base32()[:8].upper()


async def generate_qr_code(data: Dict) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(str(data))
    qr.make()
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer)
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def to_json_serializable(data: Dict) -> Dict:
    return {k: str(v) if isinstance(v, ObjectId) else to_utc_iso(v) if isinstance(v, datetime) else v for k, v in data.items()}


# Authentication
def get_password_hash(password: str) -> str:
    """Safely hash password - respects bcrypt 72-byte limit"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode('utf-8', errors='ignore')
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Safely verify password - respects bcrypt 72-byte limit"""
    plain_bytes = plain_password.encode('utf-8')
    if len(plain_bytes) > 72:
        plain_password = plain_bytes[:72].decode('utf-8', errors='ignore')
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(days=7)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
        user = users_collection.find_one({"_id": ObjectId(payload["user_id"])})
        if not user or not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="Invalid token")
        if not user.get("estate_id"):
            raise HTTPException(status_code=400, detail="User must be associated with an estate")
        users_collection.update_one({"_id": user["_id"]}, {"$set": {"last_seen": datetime.utcnow()}})
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_money_member(current_user: Dict = Depends(get_current_user)):
    """Bills, payments and the estate's books are for people who live in the
    estate (residents) and the people who run it (admins). Guards and police
    are staff/outsiders: they get gate, alert and incident data only."""
    if current_user["role"] not in ("resident", "admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Estate finances are only available to residents and admins")
    return current_user


def require_super_admin(current_user: Dict = Depends(get_current_user)):
    """Platform-owner only — every estate's data, not just one. There's no
    self-serve way to become super_admin (by design); it has to be set
    directly on the user document in MongoDB."""
    if current_user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Platform admin access required")
    return current_user


# ---------------------------------------------------------------------------
# Socket.IO Events
# ---------------------------------------------------------------------------
@sio.event
async def connect(sid, environ):
    logger.info(f"New WebSocket connection: {sid}")


@sio.event
async def disconnect(sid):
    logger.info(f"WebSocket disconnected: {sid}")


@sio.event
async def join_estate(sid, data):
    token = data.get("token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user = users_collection.find_one({"_id": ObjectId(payload["user_id"])})
        if not user or str(user.get("estate_id")) != data["estate_id"]:
            await sio.disconnect(sid)
            return
        await sio.enter_room(sid, f"estate_{data['estate_id']}")
        logger.info(f"User {payload['user_id']} joined estate {data['estate_id']}")
    except JWTError:
        await sio.disconnect(sid)


@sio.event
async def location_update(sid, data):
    # This previously took user_id/estate_id straight from whatever the
    # client sent, with no token check at all — anyone connected to the
    # socket (no login required) could broadcast a fake "guard_location"
    # event into ANY estate's room, spoofing a guard's position on a
    # security app. Now requires the same signed token join_estate uses,
    # and the broadcast target is the token's own estate, not a
    # client-supplied one.
    token = data.get("token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        return
    user = users_collection.find_one({"_id": ObjectId(payload.get("user_id"))})
    if not user or not user.get("estate_id") or user.get("role") not in ["guard", "admin", "super_admin"]:
        return
    location = data.get("location")
    if not location:
        return
    await sio.emit("guard_location", {
        "guard_id": str(user["_id"]),
        "location": location,
        "timestamp": datetime.utcnow().isoformat()
    }, room=f"estate_{user['estate_id']}")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
BUILD_VERSION = "v32-2026-10-13-estate-bills-mobile"


@app.get("/health")
async def health_check():
    # Hit this in a browser (e.g. http://localhost:8000/health) any time
    # something behaves like the old code is still running — if "build"
    # here doesn't match the marker at the top of main.py, the process
    # serving your requests isn't this file. Usually means a leftover
    # uvicorn process is still bound to the port.
    return {"status": "OK", "build": BUILD_VERSION, "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/auth/register")
async def register(user: UserCreate):
    """Public self-registration = founding a NEW estate. The registrant
    becomes that estate's admin. Estate names must be unique — if the name
    is taken, the person is told to request an invite instead. Residents,
    guards, and police only ever enter an estate via the admin invite
    endpoints below."""
    if user.role != "resident":
        raise HTTPException(status_code=400, detail="Only residents can register publicly.")

    # Each registration creates a brand-new estate, so without a limit a
    # script could flood the database with junk estates.
    now = datetime.utcnow()
    reg_key = normalize_email(user.email)
    register_rate_limit[reg_key] = [t for t in register_rate_limit[reg_key] if (now - t).total_seconds() < 3600]
    register_rate_limit["__global__"] = [t for t in register_rate_limit["__global__"] if (now - t).total_seconds() < 3600]
    if len(register_rate_limit[reg_key]) >= 3 or len(register_rate_limit["__global__"]) >= 30:
        raise HTTPException(status_code=429, detail="Too many sign-ups right now. Please try again later.")
    register_rate_limit[reg_key].append(now)
    register_rate_limit["__global__"].append(now)

    if users_collection.find_one(email_query(user.email)):
        raise HTTPException(status_code=400, detail="User already exists")

    if not user.estate_id or not str(user.estate_id).strip():
        raise HTTPException(status_code=400, detail="Estate name is required")

    estate_name = str(user.estate_id).strip()

    # SECURITY (Option A — invite-only joining):
    # Public registration can only CREATE a brand-new estate, making the
    # registrant its founding admin. It can never join an existing estate —
    # previously, anyone who typed an existing estate's exact name was
    # silently added to it as an active resident, letting strangers into
    # estates (and their visitor passes, alerts, and community) uninvited.
    # Joining an existing estate now happens exclusively through the
    # admin invite endpoints. The name check is case-insensitive so
    # "maraba estate" can't slip past "Maraba Estate".
    existing = estates_collection.find_one(
        {"name": {"$regex": f"^{re.escape(estate_name)}$", "$options": "i"}}
    )
    if existing:
        raise HTTPException(
            status_code=400,
            detail="An estate with this name already exists. If you live there, ask your estate admin to send you an invite from the app."
        )

    estate_doc = {
        "name": estate_name,
        "address": f"{estate_name}, Nigeria",
        "created_at": datetime.utcnow(),
        # Billing groundwork: every new estate starts on a 30-day trial.
        # Nothing is blocked when it ends yet — this just records the dates
        # so billing can be switched on later without migrating old estates.
        "subscription": {
            "plan": "trial",
            "status": "trialing",
            "trial_ends_at": datetime.utcnow() + timedelta(days=TRIAL_DAYS),
        },
    }
    estate_result = estates_collection.insert_one(estate_doc)
    estate_id = estate_result.inserted_id

    hashed_password = get_password_hash(user.password)

    user_dict = user.dict(exclude_unset=True, exclude={"badges"})
    user_dict.update({
        "badges": [],
        "email": normalize_email(user.email),
        "password": hashed_password,
        "estate_id": estate_id,
        "role": "resident",
        "is_active": True,
        "last_seen": datetime.utcnow(),
        "created_at": datetime.utcnow(),
        "device_tokens": []
    })

    # First user registered under an estate becomes its admin.
    if users_collection.count_documents({"estate_id": estate_id}) == 0:
        user_dict["role"] = "admin"

    result = users_collection.insert_one(user_dict)

    if user_dict.get("role") == "admin":
        estates_collection.update_one(
            {"_id": estate_id},
            {"$set": {"admin_id": result.inserted_id}}
        )

    token = create_access_token({"user_id": str(result.inserted_id), "role": user_dict["role"]})

    response_user = to_json_serializable({k: v for k, v in user_dict.items() if k != "password"})
    response_user["id"] = str(result.inserted_id)
    response_user["estate_name"] = estate_name

    audit_logs_collection.insert_one({
        "user_id": result.inserted_id,
        "estate_id": estate_id,
        "action": "create",
        "entity": "user",
        "entity_id": str(result.inserted_id),
        "details": {k: v for k, v in user_dict.items() if k != "password"},
        "timestamp": datetime.utcnow()
    })

    became_admin = user_dict.get("role") == "admin"
    send_email(
        user.email,
        f"Welcome to NexHood, {user.name.split(' ')[0]}!",
        branded_email(
            f"Welcome to {estate_name}",
            f"<p>Hi {html.escape(user.name)},</p>"
            f"<p>Your NexHood account is ready. "
            + (
                f"Since you're the first person to register {estate_name}, you're now this estate's admin — "
                f"you can invite guards, residents and police, and manage everything from the dashboard."
                if became_admin else
                f"You're all set as a resident of {estate_name}."
            )
            + "</p>"
            f"<p>From the app you can raise alerts, report incidents, issue visitor passes, and stay in the loop with what's happening around you.</p>"
            f"<p>Glad to have you on board.</p>"
        )
    )

    return {
        "message": "Registration successful! Welcome to NexHood.",
        "token": token,
        "user": response_user
    }


@app.post("/api/auth/login")
async def login(request: LoginRequest):
    # 10 attempts per 15 minutes per email — enough headroom for someone
    # who's genuinely fumbling their own password, not enough for a
    # credential-stuffing script to grind through a password list.
    email_key = request.email.lower()
    now = datetime.utcnow()
    login_rate_limit[email_key] = [t for t in login_rate_limit[email_key] if (now - t).total_seconds() < 900]
    if len(login_rate_limit[email_key]) >= 10:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please wait a few minutes and try again.")

    user = users_collection.find_one(email_query(request.email))
    if not user or not verify_password(request.password, user["password"]):
        login_rate_limit[email_key].append(now)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    login_rate_limit.pop(email_key, None)
    if user["role"] == "admin" and not user.get("estate_id"):
        raise HTTPException(status_code=400, detail="Admin must be associated with an estate")

    # Add badge if not present (gamification)
    if not any(b["badge"] == "Welcome Badge" for b in user.get("badges", [])):
        users_collection.update_one({"_id": user["_id"]}, {"$push": {"badges": BadgeAward(badge="Welcome Badge").dict()}})

    # last_seen used to only get set once, at account creation, and never
    # touched again — meaning "active users" anywhere in the app was really
    # just "everyone who ever signed up." Updating it here is what makes
    # that number (and the login log below) actually mean something.
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"last_seen": datetime.utcnow()}})
    login_logs_collection.insert_one({
        "user_id": user["_id"],
        "estate_id": user.get("estate_id"),
        "role": user["role"],
        "timestamp": datetime.utcnow()
    })

    token = create_access_token({"user_id": str(user["_id"]), "role": user["role"]})
    user_dict = to_json_serializable({k: v for k, v in user.items() if k != "password"})
    user_dict["id"] = str(user["_id"])
    user_dict["estate_id"] = str(user["estate_id"]) if user.get("estate_id") else None

    if user.get("estate_id"):
        estate = estates_collection.find_one({"_id": ObjectId(user["estate_id"])})
        if estate:
            user_dict["estate_name"] = estate.get("name")

    user_response = UserResponse(**user_dict)
    return {"message": "Login successful", "token": token, "user": user_response.dict()}


@app.post("/api/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Always returns the same generic message whether or not the email
    exists — that's intentional, so this endpoint can't be used to check
    which emails are registered."""
    # 3 reset emails per hour per address — a real user rarely needs more,
    # and it stops inbox-bombing / quota-draining abuse.
    email_key = request.email.lower()
    now = datetime.utcnow()
    reset_rate_limit[email_key] = [t for t in reset_rate_limit[email_key] if (now - t).total_seconds() < 3600]
    if len(reset_rate_limit[email_key]) >= 3:
        return {"message": "If that email is registered, a reset link has been sent."}
    reset_rate_limit[email_key].append(now)
    user = users_collection.find_one(email_query(request.email))
    if user:
        token = secrets.token_urlsafe(32)
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "reset_token": token,
                "reset_token_expires": datetime.utcnow() + timedelta(hours=1)
            }}
        )
        reset_link = f"{FRONTEND_URL}/reset-password?token={token}"
        send_email(
            user["email"],
            "Reset your NexHood password",
            branded_email(
                "Reset your password",
                f"<p>Hi {user.get('name', '')},</p>"
                f"<p>Click the button below to reset your NexHood password. This link expires in 1 hour.</p>"
                f"<p style='margin:20px 0;'><a href=\"{reset_link}\" style=\"background:#1e2a5e;color:#ffffff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;\">Reset password</a></p>"
                f"<p style='color:#9ca3af;font-size:12px;'>Or paste this link into your browser: {reset_link}</p>"
                f"<p>If you didn't request this, you can safely ignore this email.</p>"
            )
        )
    return {"message": "If that email is registered, a reset link has been sent."}


@app.post("/api/auth/reset-password")
async def reset_password(request: ResetPasswordRequest):
    user = users_collection.find_one({"reset_token": request.token})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")
    if not user.get("reset_token_expires") or datetime.utcnow() > user["reset_token_expires"]:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    hashed = get_password_hash(request.new_password)
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed}, "$unset": {"reset_token": "", "reset_token_expires": ""}}
    )

    send_email(
        user["email"],
        "Your NexHood password was changed",
        branded_email(
            "Password changed",
            f"<p>Hi {user.get('name', '')},</p>"
            f"<p>This is a confirmation that the password on your NexHood account "
            f"({user['email']}) was just reset.</p>"
            f"<p>If this was you, no action is needed.</p>"
            f"<p style='color:#b91c1c;font-weight:600;'>If you didn't request this reset, "
            f"contact your estate admin immediately — your account may be compromised.</p>"
        )
    )

    return {"message": "Password reset successfully. You can now log in with your new password."}


@app.post("/api/contact")
async def submit_contact(msg: ContactMessageCreate):
    """Landing page 'Contact us' form. Stored in Mongo first so a message
    is never lost even if the email send fails, then emails CONTACT_EMAIL
    with the details and sends the person a short confirmation so they know
    it actually went somewhere instead of vanishing into a form."""
    # 3 messages per hour per email — stops spam scripts from burning the
    # Resend quota through the public form.
    email_key = msg.email.lower()
    now = datetime.utcnow()
    contact_rate_limit[email_key] = [t for t in contact_rate_limit[email_key] if (now - t).total_seconds() < 3600]
    if len(contact_rate_limit[email_key]) >= 3:
        raise HTTPException(status_code=429, detail="Too many messages. Please try again later.")
    contact_rate_limit[email_key].append(now)
    doc = {
        "name": msg.name,
        "email": msg.email,
        "message": msg.message,
        "created_at": datetime.utcnow(),
        "status": "new"
    }
    result = contact_messages_collection.insert_one(doc)

    send_email(
        CONTACT_EMAIL,
        f"New Nexhood contact form message from {msg.name}",
        branded_email(
            "New contact form submission",
            f"<p><strong>From:</strong> {html.escape(msg.name)} ({html.escape(msg.email)})</p>"
            f"<p><strong>Message:</strong></p>"
            f"<p style='white-space:pre-wrap;'>{html.escape(msg.message)}</p>"
        )
    )
    send_email(
        msg.email,
        "We got your message — Nexhood",
        branded_email(
            "Thanks for reaching out",
            f"<p>Hi {html.escape(msg.name)},</p>"
            f"<p>Thanks for reaching out to Nexhood — we've received your message and will get back to you soon.</p>"
            f"<p style='color:#9ca3af;font-size:12px;border-left:2px solid #e5e7eb;padding-left:10px;'>{html.escape(msg.message)}</p>"
        )
    )

    return {"message": "Thanks — we've received your message and will get back to you soon.", "id": str(result.inserted_id)}


def _waitlist_estate_key(name: str) -> str:
    """'Maraba  Estate', 'maraba estate' and 'Maraba Estate ' all count as
    the same estate for the "N people from your estate" number."""
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def _new_waitlist_ref_code() -> str:
    for _ in range(10):
        code = "".join(secrets.choice(VISITOR_CODE_ALPHABET) for _ in range(6))
        if not waitlist_collection.find_one({"ref_code": code}, {"_id": 1}):
            return code
    return secrets.token_hex(4).upper()


WAITLIST_ROLE_LABELS = {
    "resident": "Resident",
    "estate_admin": "Estate admin / Exco / Facility manager",
    "security": "Security company / Guard",
    "other": "Other",
}


@app.post("/api/waitlist")
async def join_waitlist(entry: WaitlistCreate, request: Request, background_tasks: BackgroundTasks):
    """Landing-page waitlist. Completely separate from users/estates — it
    only writes to the `waitlist` collection, so nothing here can affect
    existing accounts. Duplicate phone numbers return the existing entry
    (so the person still gets their share link) instead of an error."""
    # Honeypot / too-fast submit: pretend it worked, store nothing.
    if (entry.website or "").strip() or (entry.elapsed_ms is not None and entry.elapsed_ms < 2000):
        logger.info("Waitlist submission dropped by bot filter")
        return {"ok": True, "ref_code": "", "estate_count": 0, "already_joined": False}

    now = datetime.utcnow()
    forwarded = request.headers.get("x-forwarded-for", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    for key, limit in ((f"ip:{client_ip}", 10), (f"phone:{entry.phone}", 5)):
        waitlist_rate_limit[key] = [t for t in waitlist_rate_limit[key] if (now - t).total_seconds() < 3600]
        if len(waitlist_rate_limit[key]) >= limit:
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again in a little while.")
        waitlist_rate_limit[key].append(now)

    estate_key = _waitlist_estate_key(entry.estate_name)
    email = entry.email.lower() if entry.email else None

    existing = waitlist_collection.find_one({"phone": entry.phone})
    if not existing and email:
        existing = waitlist_collection.find_one({"email": email})
    if existing:
        count = waitlist_collection.count_documents({"estate_key": existing.get("estate_key", estate_key)})
        return {"ok": True, "ref_code": existing.get("ref_code", ""), "estate_count": count, "already_joined": True}

    referred_by = None
    if entry.ref:
        ref_code = entry.ref.strip().upper()
        if waitlist_collection.find_one_and_update({"ref_code": ref_code}, {"$inc": {"referrals": 1}}):
            referred_by = ref_code

    doc = {
        "name": entry.name,
        "phone": entry.phone,
        "email": email,
        "role": entry.role,
        "estate_name": entry.estate_name,
        "estate_key": estate_key,
        "area": entry.area,
        "estate_size": entry.estate_size if entry.role == "estate_admin" else None,
        "source": entry.source,
        "referred_by": referred_by,
        "referrals": 0,
        "ref_code": _new_waitlist_ref_code(),
        "status": "new",
        "created_at": now,
    }
    waitlist_collection.insert_one(doc)
    count = waitlist_collection.count_documents({"estate_key": estate_key})

    esc = html.escape
    background_tasks.add_task(
        send_email,
        CONTACT_EMAIL,
        f"Waitlist: {entry.name} ({entry.estate_name}, {entry.area}) — {count} from this estate",
        branded_email(
            "New waitlist signup",
            f"<p><strong>{esc(entry.name)}</strong> — {esc(WAITLIST_ROLE_LABELS.get(entry.role, entry.role))}</p>"
            f"<p>Estate: {esc(entry.estate_name)} · {esc(entry.area)}"
            + (f" · size {esc(entry.estate_size)}" if doc["estate_size"] else "")
            + "</p>"
            f"<p>Phone: {esc(entry.phone)}<br/>Email: {esc(email or '—')}</p>"
            f"<p><strong>{count}</strong> signup(s) from this estate so far."
            + (f" Referred by {esc(referred_by)}." if referred_by else "")
            + "</p>"
        ),
    )
    if email:
        share_link = f"{FRONTEND_URL}/?ref={doc['ref_code']}#waitlist"
        background_tasks.add_task(
            send_email,
            email,
            "You're on the NexHood waitlist",
            branded_email(
                "You're on the list",
                f"<p>Hi {esc(entry.name.split(' ')[0])},</p>"
                f"<p>Thanks for joining the NexHood waitlist for <strong>{esc(entry.estate_name)}</strong>. "
                "We bring NexHood to estates where neighbours are asking for it, so the more people from your estate who join, the sooner we reach you.</p>"
                f"<p>Share your link with your estate WhatsApp group:<br/><a href='{share_link}'>{share_link}</a></p>"
            ),
        )

    return {"ok": True, "ref_code": doc["ref_code"], "estate_count": count, "already_joined": False}


@app.post("/api/estates")
async def create_estate(estate: EstateCreate, current_user: Dict = Depends(require_admin)):
    try:
        estate_dict = estate.dict(exclude_unset=True)
        estate_dict["admin_id"] = ObjectId(current_user["_id"])
        estate_dict["created_at"] = datetime.utcnow()
        result = estates_collection.insert_one(estate_dict)
        response_estate = to_json_serializable(estate_dict)
        response_estate["id"] = str(result.inserted_id)
        if not current_user.get("estate_id"):
            users_collection.update_one({"_id": ObjectId(current_user["_id"])}, {"$set": {"estate_id": result.inserted_id}})
        audit_logs_collection.insert_one({
            "user_id": ObjectId(current_user["_id"]),
            "estate_id": result.inserted_id,
            "action": "create",
            "entity": "estate",
            "entity_id": str(result.inserted_id),
            "details": estate_dict,
            "timestamp": datetime.utcnow()
        })
        return {"message": "Estate created successfully", "estate": response_estate}
    except Exception as e:
        logger.error(f"Error creating estate: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create estate: {str(e)}")


@app.get("/api/estates/contacts")
async def get_estate_contacts(current_user: Dict = Depends(get_current_user)):
    """Tap-to-call directory for the caller's own estate: the configured
    emergency contacts plus every active guard and admin (name + phone).
    Available to ALL roles — a resident in trouble should be able to ring
    the gate guard directly, not only 'call police'. The frontend renders
    these as tel: links so one tap opens the phone dialer."""
    estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
    emergency_contacts = (estate or {}).get("settings", {}).get("emergencyContacts", [])
    guards = list(users_collection.find(
        {"estate_id": ObjectId(current_user["estate_id"]), "role": "guard", "is_active": True},
        {"name": 1, "phone": 1}
    ))
    admins = list(users_collection.find(
        {"estate_id": ObjectId(current_user["estate_id"]), "role": "admin", "is_active": True},
        {"name": 1, "phone": 1}
    ))
    return {
        "estate_name": (estate or {}).get("name"),
        "emergency_contacts": emergency_contacts,
        "guards": [{"id": str(g["_id"]), "name": g.get("name"), "phone": g.get("phone")} for g in guards],
        "admins": [{"id": str(a["_id"]), "name": a.get("name"), "phone": a.get("phone")} for a in admins],
    }


@app.get("/api/estates/{estate_id}")
async def get_estate(estate_id: str, current_user: Dict = Depends(get_current_user)):
    """Read access: any authenticated user belonging to this estate, not
    just the exact admin who created it. This used to reject every
    resident/guard/police request with a 403 — silently, since the
    frontend swallows the error — which is why things like the Alerts
    page's police phone number (read from estate.settings) never actually
    loaded for anyone but the admin. Only mutations stay admin-gated."""
    estate = estates_collection.find_one({"_id": ObjectId(estate_id)})
    if not estate:
        raise HTTPException(status_code=404, detail="Estate not found")
    is_member = current_user.get("estate_id") and str(current_user["estate_id"]) == estate_id
    if current_user["role"] != "super_admin" and not is_member:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"estate": to_json_serializable({**estate, "id": str(estate["_id"]), "admin_id": str(estate["admin_id"])})}


@app.patch("/api/estates/{estate_id}")
async def update_estate_profile(estate_id: str, update: EstateProfileUpdate, current_user: Dict = Depends(require_admin)):
    """Admin-editable estate identity (name/address) — separate from
    /settings above, which is for the police-contact/emergency-contact
    block. Kept as its own small allowlisted route rather than folding into
    /settings so the two concerns (identity vs. escalation contacts) don't
    get tangled in one $set."""
    if current_user["role"] != "super_admin" and str(current_user.get("estate_id")) != estate_id:
        raise HTTPException(status_code=403, detail="Access denied")
    changes = update.dict(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update")
    estate = estates_collection.find_one({"_id": ObjectId(estate_id)})
    if not estate:
        raise HTTPException(status_code=404, detail="Estate not found")
    estates_collection.update_one({"_id": ObjectId(estate_id)}, {"$set": changes})
    updated = estates_collection.find_one({"_id": ObjectId(estate_id)})
    return {"estate": to_json_serializable({**updated, "id": str(updated["_id"]), "admin_id": str(updated["admin_id"])})}


# Fields an admin is allowed to self-serve edit from the Settings page.
# Deliberately a small allowlist — this endpoint does a targeted $set on
# estate.settings, not a full document replace, so anything not listed
# here just can't be touched through this route.
ESTATE_SETTINGS_ALLOWED_KEYS = {"police_email", "police_phone", "emergencyContacts", "allowGuests", "requireApproval", "maxVisitorDuration"}


@app.patch("/api/estates/{estate_id}/settings")
async def update_estate_settings(estate_id: str, settings_update: Dict = Body(...), current_user: Dict = Depends(require_admin)):
    """Lets an estate admin manage things that used to be env-var-only
    (like the police escalation number) directly from the app instead of
    needing a redeploy. super_admin can edit any estate; a regular admin
    can only edit their own."""
    if current_user["role"] != "super_admin" and str(current_user.get("estate_id")) != estate_id:
        raise HTTPException(status_code=403, detail="Access denied")

    estate = estates_collection.find_one({"_id": ObjectId(estate_id)})
    if not estate:
        raise HTTPException(status_code=404, detail="Estate not found")

    update_fields = {f"settings.{k}": v for k, v in settings_update.items() if k in ESTATE_SETTINGS_ALLOWED_KEYS}
    if not update_fields:
        raise HTTPException(status_code=400, detail=f"No valid settings provided. Allowed: {sorted(ESTATE_SETTINGS_ALLOWED_KEYS)}")

    estates_collection.update_one({"_id": ObjectId(estate_id)}, {"$set": update_fields})
    updated = estates_collection.find_one({"_id": ObjectId(estate_id)})

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(estate_id),
        "action": "update_settings",
        "entity": "estate",
        "entity_id": estate_id,
        "details": update_fields,
        "timestamp": datetime.utcnow()
    })

    return {"message": "Estate settings updated", "estate": serialize_doc({**updated, "id": str(updated["_id"])})}


@app.post("/api/visitor-passes")
async def create_visitor_pass(pass_data: VisitorPassCreate, current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["resident", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if not current_user.get("estate_id"):
        raise HTTPException(status_code=400, detail="User must be associated with an estate")
    # A pass with no sensible end date is effectively a permanent key to the
    # estate. Enforce the estate's maxVisitorDuration (hours, default 24).
    def _utc_naive(d: datetime) -> datetime:
        return (d - d.utcoffset()).replace(tzinfo=None) if d.tzinfo else d
    vf, vu = _utc_naive(pass_data.valid_from), _utc_naive(pass_data.valid_until)
    if vu <= vf:
        raise HTTPException(status_code=400, detail="The pass must end after it starts")
    estate_for_pass = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])}, {"settings": 1})
    try:
        max_hours = float(((estate_for_pass or {}).get("settings") or {}).get("maxVisitorDuration") or 24)
    except (TypeError, ValueError):
        max_hours = 24
    max_hours = min(max(max_hours, 1), 24 * 7)  # never more than 7 days
    if (vu - vf) > timedelta(hours=max_hours):
        raise HTTPException(status_code=400, detail=f"A visitor pass can last at most {int(max_hours)} hours")
    if vf > datetime.utcnow() + timedelta(days=30):
        raise HTTPException(status_code=400, detail="Passes can only be created up to 30 days ahead")
    # Lazy janitor: strip stored QR images from this estate's passes that expired
    # over 7 days ago. Pass records (names, times, gates) are kept forever for
    # history/analytics — only the heavy QR image is removed. Keeps the free
    # 512MB database self-cleaning without any cron job.
    try:
        passes_collection.update_many(
            {"estate_id": ObjectId(current_user["estate_id"]),
             "valid_until": {"$lt": datetime.utcnow() - timedelta(days=7)},
             "qr_code": {"$exists": True}},
            {"$unset": {"qr_code": ""}}
        )
    except Exception as cleanup_err:
        logger.warning(f"QR cleanup skipped: {cleanup_err}")
    code = generate_visitor_code()
    # Only check against still-active passes — once a pass is used/expired
    # its code is fair game to reuse, so we don't burn through the (small,
    # 4-char) namespace forever. Regenerate on a collision with a live one.
    while passes_collection.find_one({"code": code, "estate_id": ObjectId(current_user["estate_id"]), "status": "active"}):
        code = generate_visitor_code()
    qr_code_data = {"code": code, "estate_id": current_user["estate_id"], "type": "visitor_pass", "timestamp": datetime.utcnow().isoformat()}
    qr_code = await generate_qr_code(qr_code_data)
    pass_dict = pass_data.dict(exclude_unset=True)
    pass_dict.update({
        "code": code,
        "qr_code": qr_code,
        "host_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "status": "active",
        "created_at": datetime.utcnow()
    })
    pass_dict["host_name"] = current_user.get("name", "Resident")
    pass_dict["host_apartment"] = current_user.get("apartment") or current_user.get("address") or "N/A"
    result = passes_collection.insert_one(pass_dict)
    inserted_pass = passes_collection.find_one({"_id": result.inserted_id})
    try:
        await sio.emit("new_visitor_pass", {
            "visitor_pass": serialize_doc(inserted_pass),
            "host": current_user["name"]
        }, room=f"estate_{current_user['estate_id']}")
    except Exception as e:
        logger.error(f"Failed to emit new_visitor_pass: {e}")
    # Only emails if a visitor_email was actually given — otherwise the
    # resident just shares the code/QR they see in-app directly with their
    # guest (no SMS channel is wired up right now; see the note near
    # send_email() above).
    if pass_data.visitor_email:
        send_email(
            pass_data.visitor_email,
            f"Your NexHood visitor pass — {pass_dict['visitor_name']}",
            branded_email(
                "You've been issued a visitor pass",
                f"<p>Hi {html.escape(pass_dict['visitor_name'])},</p>"
                f"<p>Your entry code is:</p>"
                f"<p style='font-size:26px;font-weight:bold;letter-spacing:3px;color:#1e2a5e;'>{code}</p>"
                f"<p>Valid from {pass_data.valid_from} to {pass_data.valid_until}.</p>"
                f"<p>Show this code (or the QR code shared with you) to the gate guard on arrival.</p>"
            )
        )
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "create",
        "entity": "visitor_pass",
        "entity_id": str(result.inserted_id),
        "details": {k: v for k, v in pass_dict.items() if k != "qr_code"},  # QR image excluded — was bloating the DB
        "timestamp": datetime.utcnow()
    })
    return {"message": "Visitor pass created successfully", "visitor_pass": serialize_doc(inserted_pass)}


@app.post("/api/visitor-passes/{code}/validate")
async def validate_visitor_pass(code: str, pass_data: VisitorPassValidate, current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["guard", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Codes are only 4 characters and are reused once a pass is used or
    # expired, and different estates can hold the same code. Looking up by
    # code alone could pick another estate's pass (-> "Invalid visitor code")
    # or an old used pass (-> "Pass already used") for a perfectly valid
    # visitor. Always search this estate only, preferring the active pass.
    code = (code or "").strip().upper()
    estate_oid = ObjectId(current_user["estate_id"])
    pass_data_db = passes_collection.find_one({"code": code, "estate_id": estate_oid, "status": "active"}) \
        or passes_collection.find_one({"code": code, "estate_id": estate_oid}, sort=[("created_at", -1)])
    if not pass_data_db:
        raise HTTPException(status_code=404, detail="Invalid visitor code")

    now = datetime.utcnow()
    valid_from = pass_data_db["valid_from"]
    valid_until = pass_data_db["valid_until"]

    # The frontend already converts the resident's local time to a proper
    # UTC ISO timestamp before sending it (new Date(...).toISOString()), and
    # Mongo stores/returns everything as naive UTC too — so there was never
    # an actual timezone mismatch to compensate for here. The old 2-hour
    # grace window meant a code stamped "expires 9:29" was still accepted
    # at 11:29 — a real security gap, not a fix. A minute of slack is
    # plenty to absorb clock drift between the browser and this server.
    if now < valid_from - timedelta(minutes=1):
        raise HTTPException(status_code=400, detail="Pass not yet valid")
    if now > valid_until + timedelta(minutes=1):
        raise HTTPException(status_code=400, detail="Pass has expired")
    if pass_data_db["status"] == "used":
        raise HTTPException(status_code=400, detail="Pass already used")

    passes_collection.update_one(
        {"_id": pass_data_db["_id"]},
        {"$set": {"status": "used", "used_at": now, "used_by": ObjectId(current_user["_id"]), "entry_gate": pass_data.entry_gate},
         "$unset": {"qr_code": ""}}  # the QR has served its purpose — free ~10KB per pass
    )

    await sio.emit("visitor_entry", {
        "visitor_pass": serialize_doc(pass_data_db),
        "guard": current_user["name"],
        "timestamp": now.isoformat()
    }, room=f"estate_{current_user['estate_id']}")

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "validate",
        "entity": "visitor_pass",
        "entity_id": str(pass_data_db["_id"]),
        "details": {"code": code, "entry_gate": pass_data.entry_gate},
        "timestamp": now
    })

    return {
        "message": "Visitor pass validated successfully",
        "visitor_pass": to_json_serializable({
            **pass_data_db,
            "id": str(pass_data_db["_id"]),
            "used_by": str(current_user["_id"])
        })
    }


@app.post("/api/incidents")
async def create_incident(incident: IncidentCreate, background_tasks: BackgroundTasks, current_user: Dict = Depends(get_current_user)):
    incident_dict = incident.dict(exclude_unset=True)
    incident_dict.update({
        "reporter_id": ObjectId(current_user["_id"]),
        "reporter_name": current_user.get("name", "Resident"),
        # Denormalized so admins/guards can tap-to-call the reporter directly
        # from the incident view without a second lookup.
        "reporter_phone": current_user.get("phone"),
        "estate_id": ObjectId(current_user["estate_id"]),
        "status": "reported",
        "created_at": datetime.utcnow()
    })
    result = incidents_collection.insert_one(incident_dict)
    inserted_incident = incidents_collection.find_one({"_id": result.inserted_id})
    if incident.severity in ["high", "critical"]:
        await sio.emit("urgent_incident", {
            "incident": serialize_doc(inserted_incident),
            "reporter": current_user["name"]
        }, room=f"estate_{current_user['estate_id']}")
        admins = list(users_collection.find({"estate_id": ObjectId(current_user["estate_id"]), "role": {"$in": ["admin", "guard"]}, "is_active": True}, {"email": 1}))
        background_tasks.add_task(
            notify_by_email,
            [a.get("email") for a in admins if a.get("email")],
            f"NexHood ALERT: {incident.severity.upper()} incident reported",
            branded_email(
                f"{incident.severity.capitalize()} incident reported",
                f"<p><strong>{html.escape(incident.title)}</strong></p>"
                f"<p>{html.escape(incident.description)}</p>"
                f"<p>Reported by {html.escape(current_user['name'])}. Check the app for full details.</p>"
                f"<p style='margin:20px 0;'><a href=\"{LOGIN_URL}\" style=\"background:#1e2a5e;color:#ffffff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;\">Open NexHood</a></p>"
            )
        )
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "create",
        "entity": "incident",
        "entity_id": str(result.inserted_id),
        # Photos excluded from the audit copy — they live once in the incident itself.
        # Storing them twice was the single biggest use of database space.
        "details": {**{k: v for k, v in incident_dict.items() if k != "images"}, "image_count": len(incident_dict.get("images") or [])},
        "timestamp": datetime.utcnow()
    })
    return {"message": "Incident reported successfully", "incident": serialize_doc(inserted_incident)}


@app.get("/api/incidents")
async def get_incidents(status: Optional[str] = None, type: Optional[str] = None, severity: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    query_filter = {"estate_id": ObjectId(current_user["estate_id"])}
    if status:
        query_filter["status"] = status
    if type:
        query_filter["type"] = type
    if severity:
        query_filter["severity"] = severity
    if start_date and end_date:
        try:
            query_filter["created_at"] = {"$gte": datetime.fromisoformat(start_date), "$lte": datetime.fromisoformat(end_date)}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    incidents = incidents_collection.find(query_filter).sort("created_at", -1).limit(100)
    return [serialize_doc(i) for i in incidents]


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str, current_user: Dict = Depends(get_current_user)):
    """Single incident details (used by the incident detail page)."""
    incident = incidents_collection.find_one({"_id": ObjectId(incident_id)})
    if not incident or str(incident.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_doc(incident)


@app.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id: str, status: Optional[str] = None, assigned_to: Optional[str] = None, response: Optional[str] = None, title: Optional[str] = None, description: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["guard", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    incident = incidents_collection.find_one({"_id": ObjectId(incident_id)})
    if not incident or str(incident["estate_id"]) != str(current_user["estate_id"]):
        logger.error(f"Update failed for incident {incident_id}: incident={incident}, user_estate_id={current_user['estate_id']}")
        raise HTTPException(status_code=404, detail="Incident not found")
    # Editing the reported title/description is admin-only — it's a content
    # moderation action (e.g. redacting a report that names someone's
    # ethnicity/tribe as "suspicious" instead of describing actual conduct),
    # not a routine status update guards should be able to do unsupervised.
    if (title is not None or description is not None) and current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Only an admin can edit a reported incident's title or description")
    edited_content = {}
    if title is not None:
        if len(title.strip()) < 3:
            raise HTTPException(status_code=400, detail="Title must be at least 3 characters")
        edited_content["title"] = title.strip()
    if description is not None:
        if len(description.strip()) < 10:
            raise HTTPException(status_code=400, detail="Description must be at least 10 characters")
        edited_content["description"] = description.strip()
    update_set = dict(edited_content)
    if status:
        update_set["status"] = status
    if assigned_to:
        update_set["assigned_to"] = ObjectId(assigned_to)
    if status in ["resolved", "closed"]:
        update_set["resolved_at"] = datetime.utcnow()
    update_ops = {"$set": update_set}
    if response:
        update_ops["$push"] = {"responses": {"user_id": ObjectId(current_user["_id"]), "message": response, "timestamp": datetime.utcnow()}}
    incidents_collection.update_one({"_id": ObjectId(incident_id)}, update_ops)
    updated_incident = incidents_collection.find_one({"_id": ObjectId(incident_id)})
    await sio.emit("incident_updated", {
        "incident": serialize_doc(updated_incident),
        "updated_by": current_user["name"]
    }, room=f"estate_{current_user['estate_id']}")
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "edit_content" if edited_content else "update",
        "entity": "incident",
        "entity_id": incident_id,
        # When title/description were edited, keep the pre-edit values on
        # record too — accountability for a moderation action, not just a
        # routine status change.
        "details": {
            **update_ops,
            **({"previous": {k: incident.get(k) for k in edited_content}} if edited_content else {})
        },
        "timestamp": datetime.utcnow()
    })
    return {"message": "Incident updated successfully", "incident": serialize_doc(updated_incident)}


@app.patch("/api/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, current_user: Dict = Depends(get_current_user)):
    # This had neither an estate check nor a role check — any authenticated
    # user from ANY estate could resolve any OTHER estate's incidents just
    # by knowing/guessing the id. Matched to the same guard/admin-only rule
    # the sibling PATCH /api/incidents/{id} route already uses.
    if current_user["role"] not in ["guard", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    incident = incidents_collection.find_one({"_id": ObjectId(incident_id)})
    if not incident or str(incident.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="Incident not found")
    incidents_collection.update_one({"_id": ObjectId(incident_id)}, {"$set": {"status": "resolved", "resolved_at": datetime.utcnow()}})
    # Award once, like Welcome Badge above — previously this pushed a new
    # "Hero Resolver" badge on every single resolve with no dedup check, so
    # an active guard/admin's profile ended up with dozens of copies of the
    # same badge instead of it being a one-time milestone.
    resolver = users_collection.find_one({"_id": ObjectId(current_user["_id"])}, {"badges": 1})
    if not any(b["badge"] == "Hero Resolver" for b in (resolver or {}).get("badges", [])):
        users_collection.update_one({"_id": ObjectId(current_user["_id"])}, {"$push": {"badges": BadgeAward(badge="Hero Resolver").dict()}})
    return {"message": "Incident resolved"}


@app.post("/api/alerts")
async def create_alert(alert: AlertCreate, background_tasks: BackgroundTasks, current_user: Dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        current_time = datetime.utcnow()
        alert_rate_limit[user_id] = [t for t in alert_rate_limit.get(user_id, []) if (current_time - t).total_seconds() < 60]
        if len(alert_rate_limit[user_id]) >= 5:
            raise HTTPException(status_code=429, detail="Too many alerts, please try again later")
        alert_rate_limit[user_id].append(current_time)

        alert_dict = alert.dict(exclude_unset=True)
        alert_dict.update({
            "sender_id": ObjectId(current_user["_id"]),
            "sender_name": current_user.get("name", "Resident"),
            # Denormalized so admins/guards can tap-to-call whoever raised
            # the alert directly, without a second lookup.
            "sender_phone": current_user.get("phone"),
            "estate_id": ObjectId(current_user["estate_id"]),
            "sender_role": current_user["role"],
            "priority": "critical" if getattr(alert, "type", None) == "panic" else alert.priority,
            "status": "active",
            "created_at": datetime.utcnow(),
            "acknowledged_by": []
        })

        result = alerts_collection.insert_one(alert_dict)
        inserted_alert = alerts_collection.find_one({"_id": result.inserted_id})

        await sio.emit("emergency_alert", {
            "alert": serialize_doc(inserted_alert),
            "sender": current_user.get("name", "Resident")
        }, room=f"estate_{current_user['estate_id']}")

        if alert.priority in ["high", "critical"] or alert_dict["priority"] == "critical":
            estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
            emergency_contacts = (estate or {}).get("settings", {}).get("emergencyContacts", [])
            # Notify BOTH the estate's configured emergency contacts AND every
            # admin/guard of the estate. Sent as a background task so the
            # panic request itself responds immediately — email round-trips
            # must never sit between someone in danger and the "alert sent"
            # confirmation.
            staff = list(users_collection.find(
                {"estate_id": ObjectId(current_user["estate_id"]), "role": {"$in": ["admin", "guard"]}, "is_active": True},
                {"email": 1}
            ))
            recipients = [c.get("email") for c in emergency_contacts if c.get("email")] + \
                         [s.get("email") for s in staff if s.get("email")]
            background_tasks.add_task(
                notify_by_email,
                recipients,
                f"NexHood EMERGENCY ALERT ({alert_dict['priority'].upper()}): {alert.type.replace('_', ' ').title()}",
                branded_email(
                    f"{alert_dict['priority'].capitalize()} priority alert",
                    f"<p>A {alert_dict['priority']} priority alert was raised at <strong>{(estate or {}).get('name', 'your estate')}</strong>.</p>"
                    f"<p><strong>{alert.type.replace('_', ' ').title()}</strong></p>"
                    f"<p>{html.escape(alert.message or 'No details provided')}</p>"
                    f"<p>Raised by {html.escape(current_user.get('name', 'a resident'))}"
                    f"{' — ' + current_user.get('phone') if current_user.get('phone') else ''}.</p>"
                    f"<p style='margin:20px 0;'><a href=\"{LOGIN_URL}\" style=\"background:#1e2a5e;color:#ffffff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;\">Open NexHood</a></p>"
                )
            )

        audit_logs_collection.insert_one({
            "user_id": ObjectId(current_user["_id"]),
            "estate_id": ObjectId(current_user["estate_id"]),
            "action": "create",
            "entity": "alert",
            "entity_id": str(result.inserted_id),
            "details": alert_dict,
            "timestamp": datetime.utcnow()
        })

        return {"message": "Alert sent successfully", "alert": serialize_doc(inserted_alert)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert creation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create alert: {str(e)}")


@app.patch("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["guard", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    alert = alerts_collection.find_one({"_id": ObjectId(alert_id)})
    if not alert or str(alert["estate_id"]) != str(current_user["estate_id"]):
        logger.error(f"Acknowledgment failed for alert {alert_id}: alert={alert}, user_estate_id={current_user['estate_id']}")
        raise HTTPException(status_code=404, detail="Alert not found")
    if not any(ack["user_id"] == ObjectId(current_user["_id"]) for ack in alert.get("acknowledged_by", [])):
        alerts_collection.update_one(
            {"_id": ObjectId(alert_id)},
            {"$push": {"acknowledged_by": {"user_id": ObjectId(current_user["_id"]), "role": current_user["role"], "timestamp": datetime.utcnow()}},
             "$set": {"status": "acknowledged" if alert["status"] == "active" else alert["status"]}}
        )
    updated_alert = alerts_collection.find_one({"_id": ObjectId(alert_id)})
    await sio.emit("alert_acknowledged", {
        "alert": serialize_doc(updated_alert),
        "acknowledged_by": {"name": current_user["name"], "role": current_user["role"]}
    }, room=f"estate_{current_user['estate_id']}")
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "acknowledge",
        "entity": "alert",
        "entity_id": alert_id,
        "details": {"status": "acknowledged", "role": current_user["role"]},
        "timestamp": datetime.utcnow()
    })
    return {"message": "Alert acknowledged successfully", "alert": serialize_doc(updated_alert)}


@app.patch("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, current_user: Dict = Depends(get_current_user)):
    """Close out an alert. Without this, alerts only ever moved from
    active -> acknowledged and then sat there forever — there was no way
    to mark one actually handled, so the dashboard's "active alerts" count
    would only ever grow. Guards and admins can resolve."""
    if current_user["role"] not in ["guard", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    alert = alerts_collection.find_one({"_id": ObjectId(alert_id)})
    if not alert or str(alert["estate_id"]) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="Alert not found")

    alerts_collection.update_one(
        {"_id": ObjectId(alert_id)},
        {"$set": {
            "status": "resolved",
            "resolved_at": datetime.utcnow(),
            "resolved_by": ObjectId(current_user["_id"])
        }}
    )
    updated_alert = alerts_collection.find_one({"_id": ObjectId(alert_id)})
    await sio.emit("alert_resolved", {
        "alert": serialize_doc(updated_alert),
        "resolved_by": {"name": current_user["name"], "role": current_user["role"]}
    }, room=f"estate_{current_user['estate_id']}")
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "resolve",
        "entity": "alert",
        "entity_id": alert_id,
        "details": {"status": "resolved"},
        "timestamp": datetime.utcnow()
    })
    return {"message": "Alert resolved successfully", "alert": serialize_doc(updated_alert)}


@app.get("/api/alerts")
async def get_alerts(status: Optional[str] = None, type: Optional[str] = None, priority: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    query_filter = {"estate_id": ObjectId(current_user["estate_id"])}
    if status:
        query_filter["status"] = status
    if type:
        query_filter["type"] = type
    if priority:
        query_filter["priority"] = priority
    if start_date and end_date:
        try:
            query_filter["created_at"] = {"$gte": datetime.fromisoformat(start_date), "$lte": datetime.fromisoformat(end_date)}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    alerts = alerts_collection.find(query_filter).sort("created_at", -1).limit(100)
    return [serialize_doc(a) for a in alerts]


@app.post("/api/police/integration")
async def police_integration(data: PoliceIntegration, current_user: Dict = Depends(get_current_user)):
    """Any authenticated member of the estate can trigger this — a resident
    in the middle of an emergency shouldn't have to wait on a guard/admin to
    click a button on their behalf. Notifies two channels, since there's no
    real SMS/dispatch integration yet: (1) the estate's configured
    police_email/POLICE_EMAIL fallback, and (2) every active user who was
    invited with the 'police' role for this estate, emailed directly at
    their own NexHood login address — so a police account created here
    actually receives something when 'Notify police' is pressed, instead of
    that button silently going nowhere."""
    if not current_user.get("estate_id"):
        raise HTTPException(status_code=400, detail="No estate on this account")
    alert = alerts_collection.find_one({"_id": ObjectId(data.alert_id)})
    if not alert or str(alert["estate_id"]) != str(current_user.get("estate_id")):
        raise HTTPException(status_code=404, detail="Alert not found")
    # One police notification per alert per 10 minutes, and at most 5 per
    # user per hour — otherwise one tap-happy (or malicious) account could
    # flood the police inbox and get the estate's emails ignored.
    if alert.get("police_notified_at") and (datetime.utcnow() - alert["police_notified_at"]).total_seconds() < 600:
        return {"message": "Police were already notified about this alert a few minutes ago.", "status": "notified", "recipients": 0}
    uid = str(current_user["_id"])
    now_ts = datetime.utcnow()
    police_rate_limit[uid] = [t for t in police_rate_limit[uid] if (now_ts - t).total_seconds() < 3600]
    if len(police_rate_limit[uid]) >= 5:
        raise HTTPException(status_code=429, detail="Too many police notifications. Call the police directly if this is an emergency.")
    police_rate_limit[uid].append(now_ts)

    estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
    police_email = ((estate or {}).get("settings") or {}).get("police_email") or POLICE_EMAIL
    police_users = list(users_collection.find({
        "estate_id": ObjectId(current_user["estate_id"]),
        "role": "police",
        "is_active": True
    }, {"email": 1}))

    recipients = {e for e in [police_email] if e}
    recipients.update(u["email"] for u in police_users if u.get("email"))

    body = branded_email(
        "Emergency — action needed",
        f"<p><strong>Estate:</strong> {estate.get('name') if estate else 'Unknown'}</p>"
        f"<p><strong>Type:</strong> {alert.get('type', '').replace('_', ' ').title()}</p>"
        f"<p><strong>Message:</strong> {html.escape(alert.get('message') or 'No details provided')}</p>"
        f"<p><strong>Reported by:</strong> {html.escape(current_user.get('name', 'A resident'))} ({current_user.get('phone', 'no phone on file')})</p>"
        f"<p>This alert was flagged for police attention via NexHood — please respond as appropriate.</p>"
    )

    sent_count = 0
    for r in recipients:
        send_email(r, "NEXHOOD EMERGENCY — Police attention needed", body)
        sent_count += 1

    alerts_collection.update_one(
        {"_id": ObjectId(data.alert_id)},
        {"$set": {"police_status": "notified", "police_notified_at": datetime.utcnow()}}
    )

    await sio.emit("police_notified", {
        "alert_id": str(data.alert_id),
        "notified_by": current_user["name"]
    }, room=f"estate_{current_user['estate_id']}")

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "police_notify",
        "entity": "alert",
        "entity_id": data.alert_id,
        "details": {"status": "notified", "recipients": sent_count},
        "timestamp": datetime.utcnow()
    })

    if sent_count == 0:
        return {
            "message": "No police contact is set up for this estate yet — ask your admin to add one under Settings > Estate settings, or invite a police account.",
            "status": "no_recipients",
            "recipients": 0
        }

    return {
        "message": f"Police notified ({sent_count} recipient{'s' if sent_count != 1 else ''}).",
        "status": "notified",
        "recipients": sent_count
    }


@app.get("/api/users")
async def get_users(current_user: Dict = Depends(require_admin)):
    query_filter = {"estate_id": ObjectId(current_user["estate_id"]), "is_active": True}
    users = list(users_collection.find(query_filter).sort("created_at", -1))
    return [serialize_doc({"id": str(u["_id"]), **{k: v for k, v in u.items() if k != "password"}}) for u in users]



# Roles an estate-level admin is ever allowed to hand out through the app.
# "super_admin" is deliberately excluded here — that role only exists via a
# direct database edit (see require_super_admin above), and without this
# allowlist, both routes below took "role"/"new_role" as raw unvalidated
# strings, meaning any ordinary estate admin could grant themselves or
# anyone else full platform-wide access with a single request.
ASSIGNABLE_ROLES = {"resident", "guard", "admin", "police"}


@app.patch("/api/users/{user_id}")
async def update_user(user_id: str, role: Optional[str] = None, is_active: Optional[bool] = None, apartment: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user["role"] != "super_admin" and str(user.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    update_data = {}
    if role:
        if role not in ASSIGNABLE_ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {sorted(ASSIGNABLE_ROLES)}")
        if role == "admin" and user.get("role") != "admin":
            if users_collection.count_documents({"estate_id": user.get("estate_id"), "role": "admin"}) >= 3:
                raise HTTPException(status_code=400, detail="Maximum 3 admins allowed per estate")
        update_data["role"] = role
    if is_active is not None:
        update_data["is_active"] = is_active
    if apartment:
        update_data["apartment"] = apartment
    users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]) if current_user.get("estate_id") else None,
        "action": "update",
        "entity": "user",
        "entity_id": user_id,
        "details": update_data,
        "timestamp": datetime.utcnow()
    })
    return {"message": "User updated successfully", "user": to_json_serializable({**{k: v for k, v in user.items() if k != "password"}, **update_data, "id": user_id})}


@app.patch("/api/users/{user_id}/role")
async def change_user_role(user_id: str, new_role: str, current_user: Dict = Depends(require_admin)):
    if new_role not in ASSIGNABLE_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {sorted(ASSIGNABLE_ROLES)}")
    target_user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not target_user or str(target_user.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="User not found in your estate")

    if new_role == "admin":
        current_admins = users_collection.count_documents({
            "estate_id": ObjectId(current_user["estate_id"]),
            "role": "admin"
        })
        if current_admins >= 3:
            raise HTTPException(status_code=400, detail="Maximum 3 admins allowed per estate")

    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role}}
    )

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "role_change",
        "entity": "user",
        "entity_id": user_id,
        "details": {"new_role": new_role},
        "timestamp": datetime.utcnow()
    })

    return {"message": f"Role changed to {new_role}"}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, current_user: Dict = Depends(require_admin)):
    """Admin can delete any user in their estate (safety checks included)."""
    target = users_collection.find_one({"_id": ObjectId(user_id)})
    if not target or str(target.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="User not found in your estate")

    if str(target["_id"]) == str(current_user["_id"]):
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    if target.get("role") == "admin":
        admin_count = users_collection.count_documents({
            "estate_id": ObjectId(current_user["estate_id"]),
            "role": "admin"
        })
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last admin")

    users_collection.delete_one({"_id": ObjectId(user_id)})

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "delete",
        "entity": "user",
        "entity_id": user_id,
        "details": {"name": target.get("name"), "role": target.get("role")},
        "timestamp": datetime.utcnow()
    })

    return {"message": "User deleted successfully"}


@app.post("/api/users/invite")
async def single_invite(invite: UserInvite, current_user: Dict = Depends(require_admin)):
    """Admin-only single user invite.

    Admin invites are capped at 3 per estate — an estate should mostly be
    inviting residents, guards and police day-to-day; admin is a limited,
    high-trust role. Mirrors the same cap enforced in change_user_role().
    """
    if users_collection.find_one(email_query(invite.email)):
        raise HTTPException(status_code=400, detail="User already exists")

    invite_email = normalize_email(invite.email)

    if invite.role == "admin":
        current_admins = users_collection.count_documents({
            "estate_id": ObjectId(current_user["estate_id"]),
            "role": "admin"
        })
        if current_admins >= 3:
            raise HTTPException(status_code=400, detail="Maximum 3 admins allowed per estate")

    temp_password = generate_temp_password()
    hashed_password = get_password_hash(temp_password)

    user_dict = {
        "name": invite.name,
        "email": invite_email,
        "phone": invite.phone,
        "password": hashed_password,
        "role": invite.role,
        "estate_id": ObjectId(current_user["estate_id"]),
        "apartment": invite.apartment,
        "is_active": True,
        "last_seen": datetime.utcnow(),
        "created_at": datetime.utcnow(),
        "device_tokens": [],
        "badges": []
    }

    result = users_collection.insert_one(user_dict)

    # Personalize the invite with the actual estate's name (the admin's estate)
    inviting_estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
    estate_name = (inviting_estate or {}).get("name") or "your estate"

    send_email(
        invite_email,
        f"You've been invited to {estate_name}",
        branded_email(
            "You've been invited",
            f"<p>Hi {html.escape(invite.name)},</p>"
            f"<p>You've been added to <strong>{estate_name}</strong> on NexHood as a <strong>{invite.role}</strong>.</p>"
            f"<p>Login email: {invite_email}<br>Temporary password: <strong>{temp_password}</strong></p>"
            f"<p style=\"margin:24px 0;\"><a href=\"{LOGIN_URL}\" "
            f"style=\"background:#1e2a5e;color:#ffffff;text-decoration:none;padding:12px 28px;"
            f"border-radius:8px;font-weight:700;display:inline-block;\">Log in to NexHood</a></p>"
            f"<p style=\"color:#6b7280;font-size:13px;\">Or copy this link into your browser: {LOGIN_URL}</p>"
            f"<p>Please log in and change your password from Settings once you're in.</p>"
        )
    )

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "invite",
        "entity": "user",
        "entity_id": str(result.inserted_id),
        "details": {k: v for k, v in user_dict.items() if k != "password"},
        "timestamp": datetime.utcnow()
    })

    return {
        "message": "User invited successfully",
        "email": invite_email,
        # Only hand the plaintext password back to the admin if email isn't
        # configured — otherwise it's already been sent directly to the
        # invitee and there's no reason for it to also sit in the admin's
        # browser/network log.
        "temp_password": None if RESEND_API_KEY else temp_password,
        "emailed": bool(RESEND_API_KEY)
    }


@app.post("/api/users/bulk-invite")
async def bulk_invite_users(file: UploadFile = File(...), current_user: Dict = Depends(require_admin)):
    content = await file.read()
    csv_data = StringIO(content.decode("utf-8"))
    reader = csv.reader(csv_data)
    header = next(reader, None)
    if not header or len(header) < 4 or header[0].lower() != "name" or header[1].lower() != "email":
        raise HTTPException(status_code=400, detail="Invalid CSV format. Expected headers: name, email, phone, role, apartment")
    results = []
    # Track admin count locally so a CSV with several "admin" rows can't
    # blow past the 3-per-estate cap within a single upload.
    admin_count = users_collection.count_documents({
        "estate_id": ObjectId(current_user["estate_id"]),
        "role": "admin"
    })
    # Personalize invites with the estate's name — fetched once, not per row
    inviting_estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
    estate_name = (inviting_estate or {}).get("name") or "your estate"
    for row in reader:
        if not row or not row[0].strip():
            continue
        name, email, phone, role, apartment = [field.strip() for field in row[:5]] + [None] * (5 - len(row))
        email = normalize_email(email)
        role = (role or "resident").lower()
        # SECURITY: this used to accept ANY role string from the CSV —
        # including "super_admin" — so any estate admin (and anyone can
        # become one by registering a new estate) could mint a platform-wide
        # super_admin account. Same allowlist as the single-invite route.
        if role not in ASSIGNABLE_ROLES:
            results.append({"email": email, "status": "skipped", "reason": f"Invalid role '{role}'"})
            continue
        try:
            if users_collection.find_one(email_query(email)):
                results.append({"email": email, "status": "skipped", "reason": "User already exists"})
                continue
            if (role or "resident") == "admin":
                if admin_count >= 3:
                    results.append({"email": email, "status": "skipped", "reason": "Maximum 3 admins allowed per estate"})
                    continue
                admin_count += 1
            try:
                phone = normalize_phone(phone)
            except ValueError as e:
                results.append({"email": email, "status": "skipped", "reason": str(e)})
                continue
            temp_password = generate_temp_password()
            hashed_password = get_password_hash(temp_password)
            user_dict = {
                "name": name,
                "email": email,
                "phone": phone,
                "password": hashed_password,
                "role": role or "resident",
                "estate_id": ObjectId(current_user["estate_id"]),
                "apartment": apartment,
                "is_active": True,
                "last_seen": datetime.utcnow(),
                "created_at": datetime.utcnow(),
                "device_tokens": []
            }
            result_id = users_collection.insert_one(user_dict).inserted_id
            results.append({
                "email": email,
                "status": "created",
                "temp_password": None if RESEND_API_KEY else temp_password
            })
            send_email(
                email,
                f"You've been invited to {estate_name}",
                branded_email(
                    "You've been invited",
                    f"<p>Hi {html.escape(name or '')},</p>"
                    f"<p>You've been added to <strong>{estate_name}</strong> on NexHood as a <strong>{role or 'resident'}</strong>.</p>"
                    f"<p>Login email: {email}<br>Temporary password: <strong>{temp_password}</strong></p>"
                    f"<p style=\"margin:24px 0;\"><a href=\"{LOGIN_URL}\" "
                    f"style=\"background:#1e2a5e;color:#ffffff;text-decoration:none;padding:12px 28px;"
                    f"border-radius:8px;font-weight:700;display:inline-block;\">Log in to NexHood</a></p>"
                    f"<p style=\"color:#6b7280;font-size:13px;\">Or copy this link into your browser: {LOGIN_URL}</p>"
                    f"<p>Please log in and change your password from Settings once you're in.</p>"
                )
            )
            audit_logs_collection.insert_one({
                "user_id": ObjectId(current_user["_id"]),
                "estate_id": ObjectId(current_user["estate_id"]),
                "action": "create",
                "entity": "user",
                "entity_id": str(result_id),
                "details": {k: v for k, v in user_dict.items() if k != "password"},
                "timestamp": datetime.utcnow()
            })
        except Exception as e:
            results.append({"email": email, "status": "failed", "reason": str(e)})
    return {"message": "Bulk invite completed", "results": results}


# ---------------------------------------------------------------------------
# Admin analytics
# ---------------------------------------------------------------------------
# Domains that are obviously not a real police inbox (test/placeholder
# values typed during setup). Used only to flag "check your police contact".
PLACEHOLDER_EMAIL_DOMAINS = {"example.com", "test.com", "ayy.com", "email.com", "mail.com", "abc.com", "xyz.com"}
ANALYTICS_PERIODS = {7, 30, 90, 365}


def _median(values):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def _pct_change(cur, prev):
    if not prev:
        return None
    return round((cur - prev) / prev * 100)


def _first_name(name: Optional[str]) -> str:
    return (name or "Someone").strip() or "Someone"


ALERT_TYPE_LABEL = {
    "panic": "panic", "emergency": "emergency", "security_breach": "security breach",
    "fire": "fire", "medical": "medical", "general": "general",
}


def build_estate_feed(estate_filter: Dict, since: datetime, limit: int = 30) -> List[Dict]:
    """What actually happened in the estate, in plain words, newest first:
    visitors, incidents, alerts, community posts and people joining. Built
    from the real records (not the audit log) so every line can name who
    and what. Admin housekeeping lives in build_admin_log instead."""
    items: List[Dict] = []
    name_cache: Dict = {}

    def user_name(uid):
        if not uid:
            return "Someone"
        if uid not in name_cache:
            u = users_collection.find_one({"_id": uid}, {"name": 1})
            name_cache[uid] = (u or {}).get("name") or "A former resident"
        return name_cache[uid]

    for p in passes_collection.find({**estate_filter, "$or": [{"created_at": {"$gte": since}}, {"used_at": {"$gte": since}}]},
                                    {"visitor_name": 1, "host_name": 1, "host_id": 1, "created_at": 1, "used_at": 1, "status": 1}).limit(200):
        visitor = p.get("visitor_name") or "a visitor"
        host = p.get("host_name") or user_name(p.get("host_id"))
        if p.get("created_at") and p["created_at"] >= since:
            items.append({"kind": "pass_created", "at": p["created_at"], "link": "/app/visitor-passes",
                          "actor": host, "text": f"created a visitor pass for {visitor}"})
        if p.get("used_at") and p["used_at"] >= since:
            items.append({"kind": "pass_used", "at": p["used_at"], "link": "/app/visitor-passes",
                          "actor": visitor, "text": f"arrived at the gate (visiting {host})"})

    for i in incidents_collection.find({**estate_filter, "$or": [{"created_at": {"$gte": since}}, {"resolved_at": {"$gte": since}}]},
                                       {"title": 1, "severity": 1, "reporter_id": 1, "reporter_name": 1, "created_at": 1, "resolved_at": 1}).limit(200):
        title = i.get("title") or "an incident"
        link = f"/app/incidents/{i['_id']}"
        if i.get("created_at") and i["created_at"] >= since:
            items.append({"kind": "incident", "at": i["created_at"], "link": link, "level": i.get("severity"),
                          "actor": i.get("reporter_name") or user_name(i.get("reporter_id")),
                          "text": f"reported \u201c{title}\u201d ({i.get('severity', 'medium')})"})
        if i.get("resolved_at") and i["resolved_at"] >= since:
            items.append({"kind": "incident_resolved", "at": i["resolved_at"], "link": link,
                          "actor": "", "text": f"Incident \u201c{title}\u201d was resolved"})

    for a in alerts_collection.find({**estate_filter, "$or": [{"created_at": {"$gte": since}}, {"resolved_at": {"$gte": since}}]},
                                    {"type": 1, "sender_id": 1, "sender_name": 1, "created_at": 1, "resolved_at": 1, "resolved_by": 1,
                                     "acknowledged_by": 1, "police_notified_at": 1}).limit(200):
        label = ALERT_TYPE_LABEL.get(a.get("type"), "an")
        if a.get("created_at") and a["created_at"] >= since:
            items.append({"kind": "alert", "at": a["created_at"], "link": "/app/alerts", "level": "critical",
                          "actor": a.get("sender_name") or user_name(a.get("sender_id")),
                          "text": f"raised a {label} alert"})
        for ack in (a.get("acknowledged_by") or []):
            if ack.get("timestamp") and ack["timestamp"] >= since:
                items.append({"kind": "alert_ack", "at": ack["timestamp"], "link": "/app/alerts",
                              "actor": user_name(ack.get("user_id")), "text": f"responded to the {label} alert"})
        if a.get("police_notified_at") and a["police_notified_at"] >= since:
            items.append({"kind": "police", "at": a["police_notified_at"], "link": "/app/alerts",
                          "actor": "", "text": f"Police were notified about the {label} alert"})
        if a.get("resolved_at") and a["resolved_at"] >= since:
            items.append({"kind": "alert_resolved", "at": a["resolved_at"], "link": "/app/alerts",
                          "actor": user_name(a.get("resolved_by")) if a.get("resolved_by") else "",
                          "text": f"resolved the {label} alert" if a.get("resolved_by") else f"The {label} alert was resolved"})

    for po in posts_collection.find({**estate_filter, "created_at": {"$gte": since}}, {"author_name": 1, "type": 1, "content": 1, "created_at": 1}).limit(100):
        preview = (po.get("content") or "").strip().replace("\n", " ")
        preview = preview[:60] + ("\u2026" if len(preview) > 60 else "")
        what = {"event": "posted an event", "appreciation": "shared an appreciation post"}.get(po.get("type"), "posted in Community")
        items.append({"kind": "post", "at": po["created_at"], "link": "/app/community",
                      "actor": po.get("author_name") or "Someone", "text": f"{what}: \u201c{preview}\u201d"})

    for u in users_collection.find({**estate_filter, "created_at": {"$gte": since}}, {"name": 1, "role": 1, "created_at": 1}).limit(100):
        items.append({"kind": "joined", "at": u["created_at"], "link": "/app/users",
                      "actor": u.get("name") or "Someone", "text": f"joined as {u.get('role', 'resident')}"})

    items.sort(key=lambda x: x["at"], reverse=True)
    return items[:limit]


def build_admin_log(estate_filter: Dict, since: datetime, limit: int = 40) -> List[Dict]:
    """Admin actions (invites, removals, role and settings changes), with the
    person or thing they affected spelled out."""
    logs = list(audit_logs_collection.find(
        {**estate_filter, "timestamp": {"$gte": since},
         "action": {"$in": ["invite", "delete", "role_change", "update", "update_settings", "verify", "edit_content",
                            "issue_bills", "confirm_payment", "create", "approve", "void", "update_finance_settings"]},
         "entity": {"$in": ["user", "estate", "donation", "incident", "charge", "payment", "expense"]}},
        {"user_id": 1, "action": 1, "entity": 1, "entity_id": 1, "details": 1, "timestamp": 1}
    ).sort("timestamp", -1).limit(limit))
    ids = set()
    for l in logs:
        if l.get("user_id"):
            ids.add(l["user_id"])
        if l.get("entity") == "user" and l.get("entity_id") and ObjectId.is_valid(str(l["entity_id"])):
            ids.add(ObjectId(str(l["entity_id"])))
    people = {u["_id"]: u for u in users_collection.find({"_id": {"$in": list(ids)}}, {"name": 1, "role": 1})}

    out = []
    for l in logs:
        d = l.get("details") or {}
        actor = (people.get(l.get("user_id")) or {}).get("name") or "An admin"
        target_doc = people.get(ObjectId(str(l["entity_id"]))) if l.get("entity") == "user" and l.get("entity_id") and ObjectId.is_valid(str(l["entity_id"])) else None
        target = d.get("name") or (target_doc or {}).get("name")
        act, ent = l.get("action"), l.get("entity")
        if ent == "user" and act == "invite":
            text = f"invited {target or 'a new user'} as {d.get('role', 'resident')}"
        elif ent == "user" and act == "delete":
            text = f"removed {target} ({d.get('role')})" if target and d.get("role") else f"removed {target}" if target else "removed a user account"
        elif ent == "user" and act == "role_change":
            text = f"changed {target or 'a user'}'s role to {d.get('new_role', 'another role')}"
        elif ent == "user" and act == "update":
            if d.get("is_active") is False:
                text = f"deactivated {target or 'a user'}"
            elif d.get("is_active") is True:
                text = f"reactivated {target or 'a user'}"
            elif d.get("role"):
                text = f"changed {target or 'a user'}'s role to {d['role']}"
            else:
                text = f"updated {target or 'a user'}'s details"
        elif ent == "estate" and act == "update_settings":
            keys = [k.replace("settings.", "") for k in d.keys()]
            what = []
            if any(k.startswith("police") for k in keys):
                what.append("police contact")
            if "emergencyContacts" in keys:
                what.append("emergency contacts")
            if any(k in keys for k in ("allowGuests", "requireApproval", "maxVisitorDuration")):
                what.append("visitor rules")
            text = f"updated the estate's {' and '.join(what) or 'settings'}"
        elif ent == "donation" and act == "verify":
            amt = d.get("amount")
            text = f"confirmed a \u20a6{amt:,.0f} welfare pledge" if isinstance(amt, (int, float)) else "confirmed a welfare pledge"
        elif ent == "incident" and act == "edit_content":
            text = "edited an incident report"
        elif ent == "charge" and act == "issue_bills":
            text = f"issued {d.get('count', 0)} \u201c{d.get('name', 'estate')}\u201d bills for {d.get('period', '')}"
        elif ent == "payment" and act == "confirm_payment":
            text = f"confirmed a {_naira(d.get('amount'))} payment from {d.get('unit') or 'a unit'}"
        elif ent == "expense" and act == "create":
            text = f"recorded a {_naira(d.get('amount'))} expense ({CATEGORY_LABEL.get(d.get('category'), d.get('category'))})" + (" \u2014 waiting for approval" if d.get("status") == "pending_approval" else "")
        elif ent == "expense" and act == "approve":
            text = f"approved a {_naira(d.get('amount'))} expense"
        elif ent == "expense" and act == "void":
            text = f"voided a {_naira(d.get('amount'))} expense: {d.get('reason', '')}"
        elif ent == "estate" and act == "update_finance_settings":
            text = "updated the estate's bank details / approval rules"
        else:
            continue
        out.append({"kind": f"{ent}_{act}", "at": l["timestamp"], "actor": actor, "text": text})
    return out



def build_admin_analytics(estate_filter: Dict, days: int, estate: Optional[Dict]) -> Dict:
    """Everything the admin Dashboard and Analytics pages show, for the last
    `days` days, compared with the `days` before that. Estates are small
    (hundreds of records a month), so most of this is plain Python over a
    period's documents rather than heavy aggregation pipelines."""
    now = datetime.utcnow()
    start = now - timedelta(days=days)
    prev_start = start - timedelta(days=days)

    # Lazy janitor: a pass whose time is up but was never scanned used to
    # stay "active" forever, which made pass stats meaningless.
    try:
        passes_collection.update_many(
            {**estate_filter, "status": "active", "valid_until": {"$lt": now}},
            {"$set": {"status": "expired"}}
        )
    except Exception as e:
        logger.warning(f"Pass expiry sweep skipped: {e}")

    in_period = {"created_at": {"$gte": start}}
    in_prev = {"created_at": {"$gte": prev_start, "$lt": start}}

    # --- raw period data (projection keeps photos/QR images out) ---
    passes = list(passes_collection.find({**estate_filter, **in_period}, {"created_at": 1, "status": 1, "used_at": 1, "valid_from": 1}))
    incidents = list(incidents_collection.find({**estate_filter, **in_period}, {"created_at": 1, "status": 1, "type": 1, "severity": 1, "resolved_at": 1}))
    alerts = list(alerts_collection.find({**estate_filter, **in_period}, {"created_at": 1, "status": 1, "type": 1, "acknowledged_by": 1, "resolved_at": 1, "police_status": 1}))

    visitors_prev = passes_collection.count_documents({**estate_filter, **in_prev})
    incidents_prev = incidents_collection.count_documents({**estate_filter, **in_prev})
    alerts_prev = alerts_collection.count_documents({**estate_filter, **in_prev})

    # --- daily trend (every day present, zeros included) ---
    day_keys = [(start + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days + 1)]
    daily = {k: {"date": k, "visitors": 0, "incidents": 0, "alerts": 0} for k in day_keys}
    for coll, key in ((passes, "visitors"), (incidents, "incidents"), (alerts, "alerts")):
        for d in coll:
            k = d["created_at"].strftime("%Y-%m-%d")
            if k in daily:
                daily[k][key] += 1

    # --- visitor patterns (Nigeria is UTC+1, so shift hours for display) ---
    by_hour = [0] * 24
    by_weekday = [0] * 7  # Monday = 0
    for p in passes:
        t = p.get("used_at") or p.get("valid_from") or p["created_at"]
        local = t + timedelta(hours=1)
        by_hour[local.hour] += 1
        by_weekday[local.weekday()] += 1
    pass_status = {"used": 0, "active": 0, "expired": 0}
    for p in passes:
        pass_status[p.get("status", "active")] = pass_status.get(p.get("status", "active"), 0) + 1

    # --- response times ---
    ack_minutes, alert_resolve_minutes = [], []
    acknowledged = 0
    for a in alerts:
        acks = [x.get("timestamp") for x in (a.get("acknowledged_by") or []) if x.get("timestamp")]
        if acks:
            acknowledged += 1
            ack_minutes.append((min(acks) - a["created_at"]).total_seconds() / 60)
        if a.get("resolved_at"):
            alert_resolve_minutes.append((a["resolved_at"] - a["created_at"]).total_seconds() / 60)
    incident_resolve_hours = [
        (i["resolved_at"] - i["created_at"]).total_seconds() / 3600
        for i in incidents if i.get("resolved_at")
    ]

    def _count_by(items, field):
        out = {}
        for it in items:
            k = it.get(field) or "unknown"
            out[k] = out.get(k, 0) + 1
        return [{"id": k, "count": v} for k, v in sorted(out.items(), key=lambda x: -x[1])]

    # --- people ---
    users = list(users_collection.find({**estate_filter, "is_active": True}, {"name": 1, "role": 1, "last_seen": 1, "created_at": 1, "apartment": 1}))
    role_counts = {}
    for u in users:
        role_counts[u.get("role", "resident")] = role_counts.get(u.get("role", "resident"), 0) + 1
    logged_in_ids = set(login_logs_collection.distinct("user_id", {**estate_filter}))
    # login_logs only exist since login logging was added, so also treat
    # any activity well after the account was created as "has logged in".
    def _has_used_app(u):
        if u["_id"] in logged_in_ids:
            return True
        ls, ca = u.get("last_seen"), u.get("created_at")
        return bool(ls and ca and (ls - ca).total_seconds() > 300)
    never_logged_in = [u for u in users if u.get("role") != "admin" and not _has_used_app(u)]
    active_7d = sum(1 for u in users if u.get("last_seen") and u["last_seen"] >= now - timedelta(days=7))
    active_period = sum(1 for u in users if u.get("last_seen") and u["last_seen"] >= start)
    residents = [u for u in users if u.get("role") == "resident"]
    residents_dormant = sum(1 for u in residents if not u.get("last_seen") or u["last_seen"] < now - timedelta(days=30))
    residents_no_unit = sum(1 for u in residents if not (u.get("apartment") or "").strip())
    residents_active_7d = sum(1 for u in residents if u.get("last_seen") and u["last_seen"] >= now - timedelta(days=7))
    members = sorted(
        [{"name": u.get("name"), "role": u.get("role"), "unit": u.get("apartment"), "last_seen": u.get("last_seen")} for u in users],
        key=lambda m: m["last_seen"] or datetime.min, reverse=True,
    )
    logins_period = login_logs_collection.count_documents({**estate_filter, "timestamp": {"$gte": start}})

    # --- open items (not limited to the period: these need action now) ---
    open_alerts = list(alerts_collection.find({**estate_filter, "status": {"$in": ["active", "acknowledged"]}}, {"created_at": 1, "type": 1, "status": 1}).sort("created_at", 1))
    open_incidents = list(incidents_collection.find({**estate_filter, "status": {"$nin": ["resolved", "closed"]}}, {"created_at": 1, "title": 1, "severity": 1}).sort("created_at", 1))
    pending_donations = donations_collection.count_documents({**estate_filter, "status": "pending"})

    # --- needs attention ---
    attention = []
    stale_alerts = [a for a in open_alerts if a["created_at"] < now - timedelta(hours=1)]
    if stale_alerts:
        oldest_days = (now - stale_alerts[0]["created_at"]).days
        attention.append({
            "key": "stale_alerts", "level": "critical",
            "title": f"{len(stale_alerts)} alert{'s' if len(stale_alerts) != 1 else ''} still open",
            "detail": f"The oldest has been open {oldest_days} day{'s' if oldest_days != 1 else ''}. Resolve them so real emergencies stand out.",
            "link": "/app/alerts",
        })
    stale_incidents = [i for i in open_incidents if i["created_at"] < now - timedelta(hours=48)]
    if stale_incidents:
        attention.append({
            "key": "stale_incidents", "level": "warning",
            "title": f"{len(stale_incidents)} incident{'s' if len(stale_incidents) != 1 else ''} open for over 2 days",
            "detail": "Update or resolve them so residents can see they were handled.",
            "link": "/app/incidents",
        })
    if estate is not None:
        settings = (estate or {}).get("settings") or {}
        if role_counts.get("guard", 0) == 0:
            attention.append({
                "key": "no_guards", "level": "critical",
                "title": "No guards on NexHood yet",
                "detail": "Panic alerts and gate passes need guards to respond. Invite your gate guards.",
                "link": "/app/users",
            })
        police_email = (settings.get("police_email") or "").strip().lower()
        police_phone = (settings.get("police_phone") or "").strip()
        if not police_email and not police_phone and role_counts.get("police", 0) == 0:
            attention.append({
                "key": "no_police", "level": "critical",
                "title": "No police contact set",
                "detail": "\"Notify police\" has nowhere to go. Add your local division's number and email.",
                "link": "/app/settings",
            })
        elif police_email and police_email.split("@")[-1] in PLACEHOLDER_EMAIL_DOMAINS:
            attention.append({
                "key": "placeholder_police", "level": "warning",
                "title": "Police email looks like a placeholder",
                "detail": f"{police_email} doesn't look like a real inbox. Replace it with your division's email.",
                "link": "/app/settings",
            })
        if not settings.get("emergencyContacts"):
            attention.append({
                "key": "no_emergency_contacts", "level": "info",
                "title": "No emergency contacts",
                "detail": "Add the estate chairman, facility manager or a nearby clinic so residents can reach them in one tap.",
                "link": "/app/settings",
            })
    if residents and residents_dormant == len(residents):
        attention.append({
            "key": "dormant_residents", "level": "warning",
            "title": "No resident has opened NexHood in 30+ days",
            "detail": "Share the app in your estate WhatsApp group, or post an event to bring people back.",
            "link": "/app/community",
        })
    elif residents_dormant:
        attention.append({
            "key": "dormant_residents", "level": "info",
            "title": f"{residents_dormant} of {len(residents)} residents inactive for 30+ days",
            "detail": "A quick reminder in your estate WhatsApp group helps.",
            "link": "/app/users",
        })
    if never_logged_in:
        attention.append({
            "key": "never_logged_in", "level": "info",
            "title": f"{len(never_logged_in)} invited user{'s' if len(never_logged_in) != 1 else ''} never logged in",
            "detail": "They may not have seen the invite email (check spam). Confirm their email on the Users page, or send them the login link on WhatsApp.",
            "link": "/app/users",
        })
    if pending_donations:
        attention.append({
            "key": "pending_donations", "level": "info",
            "title": f"{pending_donations} welfare pledge{'s' if pending_donations != 1 else ''} to confirm",
            "detail": "Confirm the ones you've received so the campaign totals are right.",
            "link": "/app/welfare",
        })
    if estate is not None:
        pend_pay = payments_collection.count_documents({**estate_filter, "status": "pending"})
        if pend_pay:
            attention.append({
                "key": "pending_payments", "level": "warning",
                "title": f"{pend_pay} payment{'s' if pend_pay != 1 else ''} waiting for you to confirm",
                "detail": "Residents say they've paid. Check your bank, then confirm so their bills are cleared.",
                "link": "/app/payments",
            })
        pend_exp = expenses_collection.count_documents({**estate_filter, "status": "pending_approval"})
        if pend_exp:
            attention.append({
                "key": "pending_expenses", "level": "warning",
                "title": f"{pend_exp} expense{'s' if pend_exp != 1 else ''} waiting for approval",
                "detail": "Big spending only shows in the estate statement once it's approved.",
                "link": "/app/finances",
            })
        stale_repairs = requests_collection.count_documents({**estate_filter, "status": "reported", "created_at": {"$lt": now - timedelta(days=3)}})
        if stale_repairs:
            attention.append({
                "key": "stale_repairs", "level": "info",
                "title": f"{stale_repairs} repair request{'s' if stale_repairs != 1 else ''} not looked at in 3+ days",
                "detail": "Assign someone or post an update so residents know it's being handled.",
                "link": "/app/repairs",
            })
    if residents_no_unit:
        attention.append({
            "key": "residents_no_unit", "level": "info",
            "title": f"{residents_no_unit} resident{'s' if residents_no_unit != 1 else ''} without a house/flat number",
            "detail": "Ask them to add it under Settings > Profile. You'll need it for bills and service charge.",
            "link": "/app/users",
        })
    level_rank = {"critical": 0, "warning": 1, "info": 2}
    attention.sort(key=lambda x: level_rank[x["level"]])

    # --- setup checklist (estate admins only) ---
    setup = []
    if estate is not None:
        settings = (estate or {}).get("settings") or {}
        police_email = (settings.get("police_email") or "").strip().lower()
        setup = [
            {"key": "residents", "label": "Invite at least 5 residents", "done": len(residents) >= 5},
            {"key": "guards", "label": "Invite your gate guards", "done": role_counts.get("guard", 0) > 0},
            {"key": "police", "label": "Add a real police contact", "done": bool(settings.get("police_phone") or police_email) and police_email.split("@")[-1] not in PLACEHOLDER_EMAIL_DOMAINS},
            {"key": "emergency", "label": "Add emergency contacts", "done": bool(settings.get("emergencyContacts"))},
            {"key": "units", "label": "Every resident has a house/flat number", "done": bool(residents) and residents_no_unit == 0},
            {"key": "first_pass", "label": "First visitor pass scanned at the gate", "done": passes_collection.count_documents({**estate_filter, "status": "used"}) > 0},
        ]

    # --- activity ---
    recent_activity = build_estate_feed(estate_filter, start)
    admin_log = build_admin_log(estate_filter, start)

    welfare_raised_agg = list(donations_collection.aggregate([
        {"$match": {**estate_filter, "status": "verified"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))

    open_alert_count = len(open_alerts)
    return {
        "period": {"days": days, "start": start, "end": now},
        "summary": {
            # names kept from the old response so nothing else breaks
            "total_visitors": len(passes),
            "active_incidents": len(open_incidents),
            "total_alerts": len(alerts),
            "active_alerts": open_alert_count,
            "total_users": len(users),
            # new
            "visitors_prev": visitors_prev,
            "visitors_change_pct": _pct_change(len(passes), visitors_prev),
            "incidents_new": len(incidents),
            "incidents_prev": incidents_prev,
            "incidents_change_pct": _pct_change(len(incidents), incidents_prev),
            "alerts_prev": alerts_prev,
            "alerts_change_pct": _pct_change(len(alerts), alerts_prev),
            "users_active_7d": active_7d,
            "users_active_period": active_period,
            "logins_period": logins_period,
        },
        "response": {
            "alerts_total": len(alerts),
            "alerts_acknowledged": acknowledged,
            "ack_rate_pct": round(acknowledged / len(alerts) * 100) if alerts else None,
            "median_ack_minutes": _median(ack_minutes),
            "median_alert_resolve_minutes": _median(alert_resolve_minutes),
            "median_incident_resolve_hours": _median(incident_resolve_hours),
            "police_notified": sum(1 for a in alerts if a.get("police_status") == "notified"),
        },
        "people": {
            "by_role": role_counts,
            "never_logged_in": len(never_logged_in),
            "residents": len(residents),
            "residents_dormant_30d": residents_dormant,
            "residents_no_unit": residents_no_unit,
            "residents_active_7d": residents_active_7d,
            "members": members,
        },
        "visitors": {"by_hour": by_hour, "by_weekday": by_weekday, "status": pass_status},
        "trends": {
            "daily": list(daily.values()),
            # old shape, kept for compatibility
            "incidents": [{"id": d["date"], "count": d["incidents"]} for d in daily.values() if d["incidents"]],
            "visitors": [{"id": d["date"], "count": d["visitors"]} for d in daily.values() if d["visitors"]],
        },
        "distributions": {
            "incident_types": _count_by(incidents, "type"),
            "incident_severity_open": _count_by(open_incidents, "severity"),
            "users_by_role": [{"id": k, "count": v} for k, v in role_counts.items()],
            "pass_status": [{"id": k, "count": v} for k, v in pass_status.items() if v],
            "alert_status": _count_by(alerts, "status"),
            "alert_types": _count_by(alerts, "type"),
        },
        "engagement": {
            "posts_last_30d": posts_collection.count_documents({**estate_filter, **in_period}),
            "posts_period": posts_collection.count_documents({**estate_filter, **in_period}),
            "welfare_raised_total": welfare_raised_agg[0]["total"] if welfare_raised_agg else 0,
            "active_campaigns": campaigns_collection.count_documents({**estate_filter, "status": {"$ne": "closed"}}),
            "pending_donations": pending_donations,
        },
        "attention": attention,
        "setup": setup,
        "recent_activity": recent_activity,
        "admin_log": admin_log,
    }


@app.get("/api/analytics/dashboard")
async def get_dashboard(days: int = 30, current_user: Dict = Depends(get_current_user)):
    role = current_user["role"].lower()
    # A true platform-wide super_admin has no estate_id at all.
    estate_id = ObjectId(current_user["estate_id"]) if current_user.get("estate_id") else None
    if role not in ["admin", "super_admin"] and estate_id is None:
        raise HTTPException(status_code=400, detail="Account has no estate")

    if role in ["admin", "super_admin"]:
        if days not in ANALYTICS_PERIODS:
            days = 30
        estate_filter = {} if role == "super_admin" else {"estate_id": estate_id}
        estate = None if role == "super_admin" else estates_collection.find_one({"_id": estate_id}, {"settings": 1, "name": 1})
        return serialize_doc(build_admin_analytics(estate_filter, days, estate))

    now = datetime.utcnow()
    me = current_user["_id"]
    # Nigeria is UTC+1: "today" runs from local midnight.
    local_midnight = (now + timedelta(hours=1)).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(hours=1)
    open_alerts = list(alerts_collection.find({"estate_id": estate_id, "status": {"$in": ["active", "acknowledged"]}},
                                              {"type": 1, "status": 1, "created_at": 1, "sender_name": 1, "message": 1, "acknowledged_by": 1}).sort("created_at", -1).limit(10))
    base = {
        "role": role,
        "summary": {
            "active_incidents": incidents_collection.count_documents({"estate_id": estate_id, "reporter_id": me, "status": {"$nin": ["resolved", "closed"]}}),
            "total_visitors": passes_collection.count_documents({"estate_id": estate_id, "host_id": me}),
            "total_alerts": alerts_collection.count_documents({"estate_id": estate_id, "sender_id": me, "status": {"$in": ["active", "acknowledged"]}}),
            "active_alerts": len(open_alerts),
            "total_users": 0,
        },
        "recentIncidents": list(incidents_collection.find({"estate_id": estate_id, "reporter_id": me}).sort("created_at", -1).limit(5)),
        "estate_open_alerts": open_alerts,
        "open_repairs": requests_collection.count_documents({"estate_id": estate_id, "status": {"$in": ["reported", "assigned", "in_progress"]},
                                                             "$or": [{"visibility": "estate"}, {"reporter_id": me}]}),
    }

    if role in ("guard", "police"):
        # Gate view: who is expected today, who already came in.
        expected = list(passes_collection.find({
            "estate_id": estate_id, "status": "active",
            "valid_from": {"$lt": local_midnight + timedelta(days=1)}, "valid_until": {"$gte": now},
        }, {"qr_code": 0}).sort("valid_from", 1).limit(50))
        arrived = list(passes_collection.find({"estate_id": estate_id, "status": "used", "used_at": {"$gte": local_midnight}},
                                              {"qr_code": 0}).sort("used_at", -1).limit(50))
        base["gate"] = {"expected": expected, "arrived": arrived}
        base["summary"]["total_visitors"] = len(arrived)
        base["summary"]["active_incidents"] = incidents_collection.count_documents({"estate_id": estate_id, "status": {"$nin": ["resolved", "closed"]}})
    else:
        base["my_passes"] = list(passes_collection.find({"estate_id": estate_id, "host_id": me, "status": "active", "valid_until": {"$gte": now}},
                                                        {"qr_code": 0}).sort("valid_from", 1).limit(5))
        units = list(units_collection.find({"estate_id": estate_id, "$or": [{"occupant_user_ids": me}, {"payer_user_id": me}]}, {"label": 1, "credit": 1}))
        due = sum(_unit_balance(u["_id"]) for u in units)
        overdue = invoices_collection.count_documents({"unit_id": {"$in": [u["_id"] for u in units]}, "status": {"$in": ["unpaid", "part_paid"]}, "due_date": {"$lt": now}})
        base["bills"] = {"has_unit": bool(units), "balance_due": due, "overdue_bills": overdue,
                         "credit": sum(int(u.get("credit", 0)) for u in units)}
    return serialize_doc(base)


@app.get("/api/platform/stats")
async def get_platform_stats(current_user: Dict = Depends(require_super_admin)):
    """Platform-owner view across every estate — not the same thing as the
    per-estate /api/analytics/dashboard above. Answers the three things an
    app owner actually asks: how many estates/people are on here, is anyone
    logging in, and is that trending up or dead. This is app-usage data,
    not website traffic — the landing page itself isn't tracked anywhere in
    this backend (see the Vercel Web Analytics note for that half)."""
    now = datetime.utcnow()
    since_7d = now - timedelta(days=7)
    since_30d = now - timedelta(days=30)

    total_estates = estates_collection.count_documents({})
    total_users = users_collection.count_documents({"is_active": True})
    users_by_role = list(users_collection.aggregate([
        {"$match": {"is_active": True}},
        {"$group": {"_id": "$role", "count": {"$sum": 1}}}
    ]))

    logins_today = login_logs_collection.count_documents({"timestamp": {"$gte": now - timedelta(hours=24)}})
    logins_7d = login_logs_collection.count_documents({"timestamp": {"$gte": since_7d}})
    logins_30d = login_logs_collection.count_documents({"timestamp": {"$gte": since_30d}})

    login_trend = list(login_logs_collection.aggregate([
        {"$match": {"timestamp": {"$gte": since_30d}}},
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))
    signup_trend = list(users_collection.aggregate([
        {"$match": {"created_at": {"$gte": since_30d}}},
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))

    # "Active" here means someone from that estate has logged in in the
    # last 30 days — a much more honest signal than "estate exists in the
    # database," since an estate can be created and then never touched again.
    active_estate_ids = login_logs_collection.distinct("estate_id", {"timestamp": {"$gte": since_30d}})
    active_estates = len([e for e in active_estate_ids if e])

    estates_list = list(estates_collection.find({}).sort("created_at", -1).limit(50))
    estate_user_counts = {
        str(r["_id"]): r["count"] for r in users_collection.aggregate([
            {"$match": {"is_active": True}},
            {"$group": {"_id": "$estate_id", "count": {"$sum": 1}}}
        ])
    }
    estates_summary = [
        {
            "id": str(e["_id"]),
            "name": e.get("name"),
            "created_at": e.get("created_at"),
            "user_count": estate_user_counts.get(str(e["_id"]), 0)
        }
        for e in estates_list
    ]

    return {
        "summary": {
            "total_estates": total_estates,
            "active_estates_30d": active_estates,
            "total_users": total_users,
            "logins_today": logins_today,
            "logins_7d": logins_7d,
            "logins_30d": logins_30d
        },
        "users_by_role": serialize_doc(users_by_role),
        "login_trend": serialize_doc(login_trend),
        "signup_trend": serialize_doc(signup_trend),
        "estates": serialize_doc(estates_summary)
    }


@app.post("/api/sync")
async def sync_offline(actions: List[SyncAction], current_user: Dict = Depends(get_current_user)):
    results = []
    for action in actions:
        try:
            result = {"id": action.id}
            if action.type == "validate_visitor":
                # Same rule as the live validate route: only guards/admins.
                if current_user["role"] not in ["guard", "admin"]:
                    results.append({"id": action.id, "success": False, "error": "Unauthorized"})
                    continue
                pass_data = passes_collection.find_one({
                    "code": str(action.data.get("code", "")).strip().upper(),
                    "estate_id": ObjectId(current_user["estate_id"]),
                    "status": "active",
                })
                if pass_data:
                    passes_collection.update_one(
                        {"_id": pass_data["_id"]},
                        {"$set": {"status": "used", "used_at": action.timestamp, "used_by": ObjectId(current_user["_id"])}}
                    )
                    result.update({"success": True, "data": to_json_serializable({**pass_data, "id": str(pass_data["_id"])})})
                else:
                    result.update({"success": False, "error": "Invalid pass or unauthorized estate"})
            elif action.type == "create_incident":
                # Validate through the same model as the live route, so an
                # offline-sync request can't smuggle in arbitrary fields
                # (status, estate_id, reporter, etc.).
                incident_dict = IncidentCreate(**action.data).dict(exclude_unset=True)
                incident_dict.update({
                    "reporter_id": ObjectId(current_user["_id"]),
                    "estate_id": ObjectId(current_user["estate_id"]),
                    "reporter_name": current_user.get("name", "Resident"),
                    "reporter_phone": current_user.get("phone"),
                    "status": "reported",
                    "created_at": action.timestamp
                })
                result_id = incidents_collection.insert_one(incident_dict).inserted_id
                result.update({"success": True, "data": to_json_serializable({**incident_dict, "id": str(result_id)})})
            elif action.type == "create_alert":
                uid = str(current_user["_id"])
                now_ts = datetime.utcnow()
                alert_rate_limit[uid] = [t for t in alert_rate_limit.get(uid, []) if (now_ts - t).total_seconds() < 60]
                if len(alert_rate_limit[uid]) >= 5:
                    results.append({"id": action.id, "success": False, "error": "Too many alerts"})
                    continue
                alert_rate_limit[uid].append(now_ts)
                alert_dict = AlertCreate(**action.data).dict(exclude_unset=True)
                alert_dict.update({
                    "sender_id": ObjectId(current_user["_id"]),
                    "sender_name": current_user.get("name", "Resident"),
                    "sender_phone": current_user.get("phone"),
                    "sender_role": current_user["role"],
                    "estate_id": ObjectId(current_user["estate_id"]),
                    "created_at": action.timestamp,
                    "status": "active",
                    "acknowledged_by": []
                })
                result_id = alerts_collection.insert_one(alert_dict).inserted_id
                result.update({"success": True, "data": to_json_serializable({**alert_dict, "id": str(result_id)})})
            else:
                result.update({"success": False, "error": "Unknown action type"})
            results.append(result)
        except ValidationError:
            results.append({"id": action.id, "success": False, "error": "Invalid action data"})
        except Exception as e:
            results.append({"id": action.id, "success": False, "error": str(e)})
    return {"results": results}


@app.get("/api/visitor-passes")
async def get_visitor_passes(status: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    query_filter = {"estate_id": ObjectId(current_user["estate_id"])}

    # Guards work the gate, so they see every pass in the estate (not their
    # own, which they never create). Residents only see their own.
    if current_user["role"].lower() not in ["admin", "super_admin", "guard"]:
        query_filter["host_id"] = current_user["_id"]

    if status:
        query_filter["status"] = status
    if start_date and end_date:
        try:
            query_filter["created_at"] = {"$gte": datetime.fromisoformat(start_date), "$lte": datetime.fromisoformat(end_date)}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")

    projection = {"qr_code": 0} if current_user["role"].lower() == "guard" else None
    passes = passes_collection.find(query_filter, projection).sort("created_at", -1).limit(100)
    return [serialize_doc(p) for p in passes]


@app.post("/api/community/posts")
async def create_post(post: PostCreate, background_tasks: BackgroundTasks, current_user: Dict = Depends(get_current_user)):
    post_dict = post.dict()
    post_dict.update({
        "author_id": ObjectId(current_user["_id"]),
        "author_name": current_user.get("name", "Resident"),
        "author_apartment": current_user.get("apartment"),
        "author_role": current_user["role"],
        "estate_id": ObjectId(current_user["estate_id"]),
        "created_at": datetime.utcnow(),
        "likes": 0,
        "liked_by": [],
        "replies": []
    })
    result = posts_collection.insert_one(post_dict)
    await sio.emit("new_post", serialize_doc({**post_dict, "id": str(result.inserted_id)}), room=f"estate_{current_user['estate_id']}")
    # Event posts are the one community post type worth an email — people
    # shouldn't miss the estate BBQ because they didn't open the app.
    # Everyone in the estate except the author gets one, in the background.
    # General chatter and appreciation posts stay in-app only, both to keep
    # emails meaningful and to protect the Resend free-tier quota.
    if post.type == "event":
        estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
        members = list(users_collection.find(
            {"estate_id": ObjectId(current_user["estate_id"]), "is_active": True, "_id": {"$ne": current_user["_id"]}},
            {"email": 1}
        ))
        preview = post.content if len(post.content) <= 300 else post.content[:300] + "…"
        background_tasks.add_task(
            notify_by_email,
            [m.get("email") for m in members if m.get("email")],
            f"New event at {(estate or {}).get('name', 'your estate')}",
            branded_email(
                "New community event",
                f"<p><strong>{html.escape(current_user.get('name', 'A neighbour'))}</strong> posted a new event:</p>"
                f"<p style='white-space:pre-wrap;'>{html.escape(preview)}</p>"
                f"<p style='margin:20px 0;'><a href=\"{LOGIN_URL}\" style=\"background:#1e2a5e;color:#ffffff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;\">View in NexHood</a></p>"
            )
        )
    return {"post": serialize_doc({**post_dict, "id": str(result.inserted_id)})}


@app.get("/api/community/posts")
async def get_posts(current_user: Dict = Depends(get_current_user)):
    posts = list(posts_collection.find({"estate_id": ObjectId(current_user["estate_id"])}).sort("created_at", -1))
    return [serialize_doc(post) for post in posts]


@app.post("/api/community/posts/{post_id}/reply")
async def reply_to_post(post_id: str, reply_data: dict, current_user: Dict = Depends(get_current_user)):
    # Previously didn't check the post existed OR belonged to the same
    # estate — anyone logged into ANY estate could post a reply onto ANY
    # other estate's community thread just by knowing/guessing a post_id.
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post or str(post.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="Post not found")
    content = (reply_data or {}).get("content", "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Reply content is required")
    reply = {
        "author_id": ObjectId(current_user["_id"]),
        "author_name": current_user.get("name", "Resident"),
        "author_apartment": current_user.get("apartment"),
        "author_role": current_user["role"],
        "content": content,
        "created_at": datetime.utcnow()
    }
    posts_collection.update_one(
        {"_id": ObjectId(post_id)},
        {"$push": {"replies": reply}}
    )
    await sio.emit("new_reply", serialize_doc({"post_id": post_id, "reply": reply}), room=f"estate_{current_user['estate_id']}")
    return {"message": "Reply added successfully"}


@app.patch("/api/community/posts/{post_id}/like")
async def like_post(post_id: str, current_user: Dict = Depends(get_current_user)):
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post or str(post.get("estate_id")) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="Post not found")

    user_id = str(current_user["_id"])

    if user_id in (post.get("liked_by") or []):
        posts_collection.update_one(
            {"_id": ObjectId(post_id)},
            {"$pull": {"liked_by": user_id}, "$inc": {"likes": -1}}
        )
        new_likes = post.get("likes", 0) - 1
    else:
        posts_collection.update_one(
            {"_id": ObjectId(post_id)},
            {"$addToSet": {"liked_by": user_id}, "$inc": {"likes": 1}}
        )
        new_likes = post.get("likes", 0) + 1

    await sio.emit("post_update", {"id": post_id, "likes": new_likes}, room=f"estate_{current_user['estate_id']}")
    return {"message": "Like updated", "likes": new_likes}


@app.post("/api/welfare/campaigns")
async def create_campaign(campaign: WelfareCampaignCreate, current_user: Dict = Depends(require_admin)):
    """A specific cause residents can donate toward — 'New patrol vehicle',
    'Guard uniforms', 'Fuel for generators', etc — instead of just a vague
    'guards' or 'police' bucket. goal_amount is optional; leave it unset for
    an open-ended fund."""
    campaign_dict = campaign.dict()
    campaign_dict.update({
        "estate_id": ObjectId(current_user["estate_id"]),
        "created_by": ObjectId(current_user["_id"]),
        "status": "active",
        "created_at": datetime.utcnow()
    })
    result = campaigns_collection.insert_one(campaign_dict)
    return {"message": "Campaign created", "campaign": serialize_doc({**campaign_dict, "id": str(result.inserted_id)})}


@app.get("/api/welfare/campaigns")
async def list_campaigns(current_user: Dict = Depends(get_current_user)):
    """Every active campaign for the estate, with total_raised and
    donor_count computed live from the donations collection — there's no
    stored running total to keep in sync, it's always derived fresh.

    Only donations with status "verified" count toward total_raised/
    donor_count. A pledge just started at checkout (status "pending") isn't
    money in hand — there's no real Paystack webhook wired up yet to flip
    that automatically, so it stays out of the totals until an admin
    confirms it actually arrived (see /api/welfare/donations/pending and
    the /verify route below)."""
    estate_id = ObjectId(current_user["estate_id"])
    campaigns = list(campaigns_collection.find({"estate_id": estate_id}).sort("created_at", -1))

    totals = list(donations_collection.aggregate([
        {"$match": {"estate_id": estate_id, "campaign_id": {"$ne": None}, "status": "verified"}},
        {"$group": {"_id": "$campaign_id", "total_raised": {"$sum": "$amount"}, "donor_count": {"$sum": 1}}}
    ]))
    totals_map = {str(t["_id"]): t for t in totals}

    result = []
    for c in campaigns:
        stats = totals_map.get(str(c["_id"]), {"total_raised": 0, "donor_count": 0})
        result.append(serialize_doc({
            **c,
            "id": str(c["_id"]),
            "total_raised": stats["total_raised"],
            "donor_count": stats["donor_count"]
        }))
    return result


@app.post("/api/welfare/donate")
async def donate(donation: DonationCreate, current_user: Dict = Depends(get_current_user)):
    """IMPORTANT — this does not move real money yet. There's no Paystack
    account wired in, so the "paystack_link" below is a placeholder, not a
    real checkout URL. To make this real: 1) get a Paystack secret key,
    2) call Paystack's /transaction/initialize with the amount + a callback
    URL to get a real authorization_url, 3) add a webhook route Paystack
    calls on success, which should flip this donation's status to
    "verified" automatically. Until that webhook exists, every donation
    here sits at "pending" and an admin has to manually confirm it actually
    arrived (via /api/welfare/donations/{id}/verify) before it counts
    toward any total — see list_campaigns above."""
    if donation.campaign_id:
        campaign = campaigns_collection.find_one({"_id": ObjectId(donation.campaign_id)})
        if not campaign or str(campaign["estate_id"]) != str(current_user["estate_id"]):
            raise HTTPException(status_code=404, detail="Campaign not found")

    donation_dict = donation.dict(exclude={"campaign_id"})
    donation_dict.update({
        "user_id": ObjectId(current_user["_id"]),
        "donor_name": current_user.get("name"),
        "estate_id": ObjectId(current_user["estate_id"]),
        "campaign_id": ObjectId(donation.campaign_id) if donation.campaign_id else None,
        "timestamp": datetime.utcnow(),
        "status": "pending"
    })
    result = donations_collection.insert_one(donation_dict)
    # SECURITY: this used to return a made-up link like
    # paystack.com/pay/nexhood-guards-5000. Anyone could create a Paystack
    # page with that name and collect residents' money. No link is returned
    # until a real Paystack integration exists; the frontend shows the
    # admin's payment instructions instead.
    return {"paystack_link": None, "donation_id": str(result.inserted_id), "status": "pending"}


@app.get("/api/welfare/donations/pending")
async def list_pending_donations(current_user: Dict = Depends(require_admin)):
    """Pledges awaiting manual confirmation — see the note on donate() above
    about why this has to be manual for now."""
    estate_id = ObjectId(current_user["estate_id"])
    donations = list(donations_collection.find({"estate_id": estate_id, "status": "pending"}).sort("timestamp", -1))
    return [serialize_doc({**d, "id": str(d["_id"])}) for d in donations]


@app.patch("/api/welfare/donations/{donation_id}/verify")
async def verify_donation(donation_id: str, current_user: Dict = Depends(require_admin)):
    """Admin confirms a pledge actually arrived (bank transfer, cash, etc.)
    — only then does it count toward a campaign's total_raised."""
    donation = donations_collection.find_one({"_id": ObjectId(donation_id)})
    if not donation or str(donation["estate_id"]) != str(current_user["estate_id"]):
        raise HTTPException(status_code=404, detail="Donation not found")
    if donation.get("status") == "verified":
        raise HTTPException(status_code=400, detail="Already verified")
    donations_collection.update_one(
        {"_id": ObjectId(donation_id)},
        {"$set": {"status": "verified", "verified_by": ObjectId(current_user["_id"]), "verified_at": datetime.utcnow()}}
    )
    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]),
        "action": "verify",
        "entity": "donation",
        "entity_id": donation_id,
        "details": {"amount": donation.get("amount")},
        "timestamp": datetime.utcnow()
    })
    return {"message": "Donation verified"}


MAX_UPLOAD_BYTES = 3 * 1024 * 1024  # 3MB — images are embedded straight into
# the Mongo document (no object storage), so this cap keeps posts sane. The
# frontend also checks this client-side before ever hitting this route.


@app.post("/api/upload/image")
async def upload_image(file: UploadFile = File(...), current_user: Dict = Depends(get_current_user)):
    try:
        content = await file.read()
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Image too large (max 3MB)")
        img_base64 = base64.b64encode(content).decode("utf-8")
        content_type = file.content_type or "image/jpeg"
        # Returned as a ready-to-use data URI so callers don't have to
        # separately track/re-attach the mime type.
        return {"image_url": f"data:{content_type};base64,{img_base64}"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Upload failed: {str(e)}")


@app.get("/api/users/me")
async def get_my_profile(current_user: Dict = Depends(get_current_user)):
    """Returns the currently logged-in user with estate name.

    IMPORTANT: this used to be named `get_current_user`, which shadowed the
    auth dependency function of the same name — every route defined below it
    that used Depends(get_current_user) silently got THIS function instead,
    breaking (at minimum) password change. Renamed to fix that; keep this
    function's name different from the dependency above.
    """
    user_data = serialize_doc({k: v for k, v in current_user.items() if k != "password"})
    if current_user.get("estate_id"):
        estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
        if estate:
            user_data["estate_name"] = estate.get("name")
    return user_data


@app.patch("/api/users/me")
async def update_my_profile(update: ProfileUpdate, current_user: Dict = Depends(get_current_user)):
    """Self-serve profile edits — name, phone, email, apartment. Nothing
    here touches role or estate membership; those stay admin-controlled.
    Changing email just updates the login address on this same account, no
    re-verification flow yet (matches how the rest of the app currently
    trusts email at signup)."""
    changes = update.dict(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update")

    if "email" in changes:
        changes["email"] = normalize_email(changes["email"])
        if changes["email"] != current_user["email"].lower():
            dup_query = email_query(changes["email"])
            dup_query["_id"] = {"$ne": ObjectId(current_user["_id"])}
            if users_collection.find_one(dup_query):
                raise HTTPException(status_code=400, detail="That email is already in use")

    users_collection.update_one({"_id": ObjectId(current_user["_id"])}, {"$set": changes})

    updated = users_collection.find_one({"_id": ObjectId(current_user["_id"])})
    user_data = serialize_doc({k: v for k, v in updated.items() if k != "password"})
    if updated.get("estate_id"):
        estate = estates_collection.find_one({"_id": ObjectId(updated["estate_id"])})
        if estate:
            user_data["estate_name"] = estate.get("name")

    audit_logs_collection.insert_one({
        "user_id": ObjectId(current_user["_id"]),
        "estate_id": ObjectId(current_user["estate_id"]) if current_user.get("estate_id") else None,
        "action": "update",
        "entity": "user_profile",
        "entity_id": str(current_user["_id"]),
        "details": changes,
        "timestamp": datetime.utcnow()
    })

    return user_data


@app.patch("/api/users/me/password")
async def change_password(data: dict, current_user: Dict = Depends(get_current_user)):
    """Any logged-in user (resident, guard, admin, police) can change their
    own password. Expects: { "old_password": "...", "new_password": "..." }
    """
    if not verify_password(data.get("old_password", ""), current_user["password"]):
        raise HTTPException(status_code=400, detail="Old password is incorrect")

    if len(data.get("new_password", "")) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    hashed_new = get_password_hash(data["new_password"])
    users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"password": hashed_new}}
    )

    # Security notification — lets the real owner know immediately if
    # someone else (or they themselves) just changed the password, so a
    # compromised account doesn't go unnoticed silently.
    send_email(
        current_user["email"],
        "Your NexHood password was changed",
        branded_email(
            "Password changed",
            f"<p>Hi {current_user.get('name', '')},</p>"
            f"<p>This is a confirmation that the password on your NexHood account "
            f"({current_user['email']}) was just changed.</p>"
            f"<p>If this was you, no action is needed.</p>"
            f"<p style='color:#b91c1c;font-weight:600;'>If you didn't make this change, "
            f"contact your estate admin or reply to this email immediately — your account "
            f"may be compromised.</p>"
        )
    )

    return {"message": "Password changed successfully"}


# ===========================================================================
# ESTATE MONEY (Phase 1): units, bills, payments, estate balance, expenses,
# monthly statement — plus facility (repair) requests.
#
# NexHood never holds money. Residents pay the estate's own bank account
# (bank transfer / cash for now; Paystack later). NexHood records who owes
# what, who paid, and how the money was spent, so every resident can see it.
# Amounts are whole naira (int).
# ===========================================================================
units_collection = db["units"]
charges_collection = db["charges"]
invoices_collection = db["invoices"]
payments_collection = db["payments"]
expenses_collection = db["expenses"]
requests_collection = db["facility_requests"]
try:
    units_collection.create_index("estate_id")
    invoices_collection.create_index([("estate_id", 1), ("unit_id", 1), ("status", 1)])
    invoices_collection.create_index([("charge_id", 1), ("period", 1), ("unit_id", 1)])
    payments_collection.create_index([("estate_id", 1), ("status", 1)])
    expenses_collection.create_index([("estate_id", 1), ("date", -1)])
    requests_collection.create_index([("estate_id", 1), ("created_at", -1)])
except Exception as e:
    logger.error(f"Finance index creation failed (non-fatal): {e}")

CHARGE_CATEGORIES = ("service_charge", "security", "power", "water", "waste", "special", "other")
CHARGE_FREQUENCIES = ("one_off", "monthly", "quarterly", "yearly")
EXPENSE_CATEGORIES = ("diesel_power", "security_salaries", "repairs", "cleaning_waste", "water", "admin", "other")
REQUEST_CATEGORIES = ("plumbing", "electrical", "roof_building", "road", "drainage", "waste", "gate_fence", "water", "other")
REQUEST_STATUSES = ("reported", "assigned", "in_progress", "fixed", "closed")
PAYMENT_METHODS = ("bank_transfer", "cash", "pos", "paystack")
MAX_PROOF_CHARS = int(1.5 * 1024 * 1024)  # data URI size cap for receipts/proofs

CATEGORY_LABEL = {
    "service_charge": "Service charge", "security": "Security levy", "power": "Power / diesel",
    "water": "Water", "waste": "Waste", "special": "Special levy", "other": "Other",
    "diesel_power": "Diesel & power", "security_salaries": "Security salaries", "repairs": "Repairs & maintenance",
    "cleaning_waste": "Cleaning & waste", "admin": "Admin & bank charges",
}


def _oid(value: str, what: str = "item") -> ObjectId:
    if not value or not ObjectId.is_valid(str(value)):
        raise HTTPException(status_code=404, detail=f"{what.capitalize()} not found")
    return ObjectId(str(value))


def _naira(n) -> str:
    try:
        return f"₦{int(round(float(n))):,}"
    except (TypeError, ValueError):
        return "₦0"


def _estate_oid(user: Dict) -> ObjectId:
    return ObjectId(user["estate_id"])


def _finance_settings(estate_id: ObjectId) -> Dict:
    estate = estates_collection.find_one({"_id": estate_id}, {"finance": 1}) or {}
    return estate.get("finance") or {}


def _is_admin(user: Dict) -> bool:
    return user.get("role") in ("admin", "super_admin")


def _unit_balance(unit_id: ObjectId) -> int:
    """What a unit still owes across all open bills."""
    agg = list(invoices_collection.aggregate([
        {"$match": {"unit_id": unit_id, "status": {"$in": ["unpaid", "part_paid"]}}},
        {"$group": {"_id": None, "due": {"$sum": {"$subtract": ["$amount", "$amount_paid"]}}}},
    ]))
    return int(agg[0]["due"]) if agg else 0


def _apply_to_unit(unit_id: ObjectId, amount: int, preferred_invoice: Optional[ObjectId] = None) -> Dict:
    """Spread `amount` over the unit's open bills (the chosen bill first, then
    oldest first). Anything left over becomes estate-balance credit."""
    remaining = int(amount)
    applied = []
    open_bills = list(invoices_collection.find({"unit_id": unit_id, "status": {"$in": ["unpaid", "part_paid"]}}).sort("due_date", 1))
    if preferred_invoice:
        open_bills.sort(key=lambda b: 0 if b["_id"] == preferred_invoice else 1)
    for bill in open_bills:
        if remaining <= 0:
            break
        due = int(bill["amount"]) - int(bill.get("amount_paid", 0))
        if due <= 0:
            continue
        pay = min(due, remaining)
        new_paid = int(bill.get("amount_paid", 0)) + pay
        invoices_collection.update_one({"_id": bill["_id"]}, {"$set": {
            "amount_paid": new_paid,
            "status": "paid" if new_paid >= int(bill["amount"]) else "part_paid",
            **({"paid_at": datetime.utcnow()} if new_paid >= int(bill["amount"]) else {}),
        }})
        applied.append({"invoice_id": bill["_id"], "amount": pay})
        remaining -= pay
    if remaining > 0:
        units_collection.update_one({"_id": unit_id}, {"$inc": {"credit": remaining}})
    return {"applied": applied, "to_credit": max(remaining, 0)}


def _unit_payer_emails(unit: Dict) -> List[str]:
    ids = [i for i in [unit.get("payer_user_id")] + list(unit.get("occupant_user_ids") or []) if i]
    if not ids:
        return []
    return [u["email"] for u in users_collection.find({"_id": {"$in": ids}, "is_active": True}, {"email": 1}) if u.get("email")]


def _serialize_unit(u: Dict, people: Optional[Dict] = None) -> Dict:
    people = people or {}
    occupants = [people.get(i) for i in (u.get("occupant_user_ids") or []) if people.get(i)]
    payer = people.get(u.get("payer_user_id"))
    return serialize_doc({
        **u,
        "credit": int(u.get("credit", 0)),
        "balance_due": _unit_balance(u["_id"]),
        "occupants": [{"id": str(p["_id"]), "name": p.get("name"), "role": p.get("role")} for p in occupants],
        "payer": {"id": str(payer["_id"]), "name": payer.get("name")} if payer else None,
    })


# ---------------- finance settings ----------------
class FinanceSettingsUpdate(BaseModel):
    bank_name: Optional[str] = Field(None, max_length=60)
    account_name: Optional[str] = Field(None, max_length=100)
    account_number: Optional[str] = Field(None, max_length=20)
    approver_user_id: Optional[str] = None
    approval_threshold: Optional[int] = Field(None, ge=0)


@app.get("/api/finance/settings")
async def get_finance_settings(current_user: Dict = Depends(require_money_member)):
    s = _finance_settings(_estate_oid(current_user))
    approver = None
    if s.get("approver_user_id"):
        a = users_collection.find_one({"_id": s["approver_user_id"]}, {"name": 1})
        approver = {"id": str(s["approver_user_id"]), "name": (a or {}).get("name")}
    return {
        "bank_name": s.get("bank_name"), "account_name": s.get("account_name"), "account_number": s.get("account_number"),
        "approval_threshold": int(s.get("approval_threshold", 100000)), "approver": approver,
    }


@app.patch("/api/finance/settings")
async def update_finance_settings(body: FinanceSettingsUpdate, current_user: Dict = Depends(require_admin)):
    estate_id = _estate_oid(current_user)
    changes = {}
    data = body.dict(exclude_unset=True)
    for k in ("bank_name", "account_name", "account_number", "approval_threshold"):
        if k in data and data[k] is not None:
            changes[f"finance.{k}"] = data[k].strip() if isinstance(data[k], str) else data[k]
    if "approver_user_id" in data:
        if data["approver_user_id"]:
            approver = users_collection.find_one({"_id": _oid(data["approver_user_id"], "user"), "estate_id": estate_id, "role": "admin", "is_active": True})
            if not approver:
                raise HTTPException(status_code=400, detail="The approver must be an admin of this estate")
            changes["finance.approver_user_id"] = approver["_id"]
        else:
            changes["finance.approver_user_id"] = None
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update")
    estates_collection.update_one({"_id": estate_id}, {"$set": changes})
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": estate_id, "action": "update_finance_settings",
                                      "entity": "estate", "details": {k: str(v) for k, v in changes.items()}, "timestamp": datetime.utcnow()})
    return await get_finance_settings(current_user)


# ---------------- units ----------------
class UnitCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=60)
    unit_type: Optional[str] = Field(None, max_length=40)
    owner_name: Optional[str] = Field(None, max_length=80)
    payer_user_id: Optional[str] = None
    occupant_user_ids: Optional[List[str]] = None


class UnitUpdate(BaseModel):
    label: Optional[str] = Field(None, min_length=1, max_length=60)
    unit_type: Optional[str] = Field(None, max_length=40)
    owner_name: Optional[str] = Field(None, max_length=80)
    payer_user_id: Optional[str] = None
    occupant_user_ids: Optional[List[str]] = None
    active: Optional[bool] = None


def _resolve_members(estate_id: ObjectId, ids: Optional[List[str]]) -> List[ObjectId]:
    out = []
    for i in ids or []:
        u = users_collection.find_one({"_id": _oid(i, "user"), "estate_id": estate_id}, {"_id": 1})
        if not u:
            raise HTTPException(status_code=400, detail="Everyone on a unit must belong to this estate")
        out.append(u["_id"])
    return out


@app.get("/api/units")
async def list_units(current_user: Dict = Depends(require_money_member)):
    estate_id = _estate_oid(current_user)
    q = {"estate_id": estate_id}
    if not _is_admin(current_user):
        q["$or"] = [{"occupant_user_ids": current_user["_id"]}, {"payer_user_id": current_user["_id"]}]
    units = list(units_collection.find(q).sort("label", 1))
    ids = set()
    for u in units:
        ids.update(u.get("occupant_user_ids") or [])
        if u.get("payer_user_id"):
            ids.add(u["payer_user_id"])
    people = {p["_id"]: p for p in users_collection.find({"_id": {"$in": list(ids)}}, {"name": 1, "role": 1})}
    return [_serialize_unit(u, people) for u in units]


@app.post("/api/units")
async def create_unit(body: UnitCreate, current_user: Dict = Depends(require_admin)):
    estate_id = _estate_oid(current_user)
    label = re.sub(r"\s+", " ", body.label).strip()
    if units_collection.find_one({"estate_id": estate_id, "label": {"$regex": f"^{re.escape(label)}$", "$options": "i"}}):
        raise HTTPException(status_code=400, detail="A unit with that name already exists")
    occupants = _resolve_members(estate_id, body.occupant_user_ids)
    payer = _resolve_members(estate_id, [body.payer_user_id])[0] if body.payer_user_id else (occupants[0] if occupants else None)
    doc = {"estate_id": estate_id, "label": label, "unit_type": (body.unit_type or "").strip() or None,
           "owner_name": body.owner_name, "occupant_user_ids": occupants, "payer_user_id": payer,
           "credit": 0, "active": True, "created_at": datetime.utcnow()}
    res = units_collection.insert_one(doc)
    if occupants:
        users_collection.update_many({"_id": {"$in": occupants}}, {"$set": {"unit_id": res.inserted_id, "apartment": label}})
    return _serialize_unit({**doc, "_id": res.inserted_id})


@app.patch("/api/units/{unit_id}")
async def update_unit(unit_id: str, body: UnitUpdate, current_user: Dict = Depends(require_admin)):
    estate_id = _estate_oid(current_user)
    unit = units_collection.find_one({"_id": _oid(unit_id, "unit"), "estate_id": estate_id})
    if not unit:
        raise HTTPException(status_code=404, detail="Unit not found")
    data = body.dict(exclude_unset=True)
    changes = {}
    if "label" in data and data["label"]:
        changes["label"] = re.sub(r"\s+", " ", data["label"]).strip()
    for k in ("unit_type", "owner_name", "active"):
        if k in data:
            changes[k] = data[k]
    if "occupant_user_ids" in data:
        occ = _resolve_members(estate_id, data["occupant_user_ids"])
        changes["occupant_user_ids"] = occ
        users_collection.update_many({"unit_id": unit["_id"], "_id": {"$nin": occ}}, {"$unset": {"unit_id": ""}})
        if occ:
            users_collection.update_many({"_id": {"$in": occ}}, {"$set": {"unit_id": unit["_id"], "apartment": changes.get("label", unit["label"])}})
    if "payer_user_id" in data:
        changes["payer_user_id"] = _resolve_members(estate_id, [data["payer_user_id"]])[0] if data["payer_user_id"] else None
    if changes:
        units_collection.update_one({"_id": unit["_id"]}, {"$set": changes})
    return _serialize_unit(units_collection.find_one({"_id": unit["_id"]}))


@app.post("/api/units/import-from-residents")
async def import_units_from_residents(current_user: Dict = Depends(require_admin)):
    """Quick start: turn every resident's flat number into a unit and link
    them to it. Residents with the same flat number share one unit."""
    estate_id = _estate_oid(current_user)
    created, linked = 0, 0
    for r in users_collection.find({"estate_id": estate_id, "role": "resident", "is_active": True}):
        label = re.sub(r"\s+", " ", (r.get("apartment") or "")).strip()
        if not label or r.get("unit_id"):
            continue
        unit = units_collection.find_one({"estate_id": estate_id, "label": {"$regex": f"^{re.escape(label)}$", "$options": "i"}})
        if not unit:
            uid = units_collection.insert_one({"estate_id": estate_id, "label": label, "unit_type": None, "owner_name": None,
                                               "occupant_user_ids": [r["_id"]], "payer_user_id": r["_id"], "credit": 0,
                                               "active": True, "created_at": datetime.utcnow()}).inserted_id
            created += 1
        else:
            uid = unit["_id"]
            units_collection.update_one({"_id": uid}, {"$addToSet": {"occupant_user_ids": r["_id"]}})
            if not unit.get("payer_user_id"):
                units_collection.update_one({"_id": uid}, {"$set": {"payer_user_id": r["_id"]}})
        users_collection.update_one({"_id": r["_id"]}, {"$set": {"unit_id": uid}})
        linked += 1
    return {"created": created, "linked": linked}


# ---------------- charges (bill types) & invoices ----------------
class ChargeCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    category: str = "service_charge"
    amount: int = Field(..., gt=0)
    frequency: str = "monthly"
    type_amounts: Optional[Dict[str, int]] = None  # e.g. {"duplex": 40000}

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if v not in CHARGE_CATEGORIES:
            raise ValueError("Unknown bill category")
        return v

    @field_validator("frequency")
    @classmethod
    def _freq(cls, v):
        if v not in CHARGE_FREQUENCIES:
            raise ValueError("Unknown frequency")
        return v


class ChargeUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=80)
    amount: Optional[int] = Field(None, gt=0)
    type_amounts: Optional[Dict[str, int]] = None
    active: Optional[bool] = None


class IssueBills(BaseModel):
    period: str = Field(..., min_length=4, max_length=20)  # e.g. "2026-10" or "2026" or "Q4 2026"
    due_date: datetime
    unit_ids: Optional[List[str]] = None  # default: all active units


@app.get("/api/charges")
async def list_charges(current_user: Dict = Depends(require_money_member)):
    return [serialize_doc(c) for c in charges_collection.find({"estate_id": _estate_oid(current_user)}).sort("created_at", -1)]


@app.post("/api/charges")
async def create_charge(body: ChargeCreate, current_user: Dict = Depends(require_admin)):
    doc = {**body.dict(), "estate_id": _estate_oid(current_user), "active": True,
           "created_by": current_user["_id"], "created_at": datetime.utcnow()}
    res = charges_collection.insert_one(doc)
    return serialize_doc({**doc, "_id": res.inserted_id})


@app.patch("/api/charges/{charge_id}")
async def update_charge(charge_id: str, body: ChargeUpdate, current_user: Dict = Depends(require_admin)):
    q = {"_id": _oid(charge_id, "bill type"), "estate_id": _estate_oid(current_user)}
    if not charges_collection.find_one(q):
        raise HTTPException(status_code=404, detail="Bill type not found")
    changes = {k: v for k, v in body.dict(exclude_unset=True).items()}
    if changes:
        charges_collection.update_one(q, {"$set": changes})
    return serialize_doc(charges_collection.find_one(q))


@app.post("/api/charges/{charge_id}/issue")
async def issue_bills(charge_id: str, body: IssueBills, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_admin)):
    """Create one bill per unit for this charge and period. Safe to run
    twice: units that already have this bill for this period are skipped.
    Any estate-balance credit a unit has is used up first."""
    estate_id = _estate_oid(current_user)
    charge = charges_collection.find_one({"_id": _oid(charge_id, "bill type"), "estate_id": estate_id})
    if not charge or not charge.get("active", True):
        raise HTTPException(status_code=404, detail="Bill type not found")
    uq = {"estate_id": estate_id, "active": True}
    if body.unit_ids:
        uq["_id"] = {"$in": [_oid(u, "unit") for u in body.unit_ids]}
    units = list(units_collection.find(uq))
    if not units:
        raise HTTPException(status_code=400, detail="Add your houses/flats under Units before issuing bills")
    due = body.due_date
    if due.tzinfo is not None:
        due = (due - due.utcoffset()).replace(tzinfo=None)
    period = body.period.strip()
    issued, skipped, emails = 0, 0, []
    for u in units:
        if invoices_collection.find_one({"charge_id": charge["_id"], "period": period, "unit_id": u["_id"], "status": {"$ne": "void"}}):
            skipped += 1
            continue
        amount = int((charge.get("type_amounts") or {}).get(u.get("unit_type") or "", charge["amount"]))
        inv = {"estate_id": estate_id, "unit_id": u["_id"], "unit_label": u["label"], "charge_id": charge["_id"],
               "title": f"{charge['name']} — {period}", "category": charge["category"], "period": period,
               "amount": amount, "amount_paid": 0, "status": "unpaid", "due_date": due,
               "created_by": current_user["_id"], "created_at": datetime.utcnow()}
        res = invoices_collection.insert_one(inv)
        credit = int(u.get("credit", 0))
        if credit > 0:
            use = min(credit, amount)
            units_collection.update_one({"_id": u["_id"]}, {"$inc": {"credit": -use}})
            invoices_collection.update_one({"_id": res.inserted_id}, {"$set": {
                "amount_paid": use, "status": "paid" if use >= amount else "part_paid",
                "paid_from_credit": use, **({"paid_at": datetime.utcnow()} if use >= amount else {})}})
        issued += 1
        emails.extend(_unit_payer_emails(u))
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": estate_id, "action": "issue_bills", "entity": "charge",
                                      "entity_id": str(charge["_id"]), "details": {"name": charge["name"], "period": period, "count": issued},
                                      "timestamp": datetime.utcnow()})
    if emails:
        fin = _finance_settings(estate_id)
        bank = (f"<p>Pay by bank transfer to <strong>{html.escape(fin.get('account_name') or '')}</strong>, "
                f"{html.escape(fin.get('bank_name') or '')} {html.escape(fin.get('account_number') or '')}, then tap "
                f"“I’ve paid” in NexHood and attach your receipt.</p>") if fin.get("account_number") else ""
        background_tasks.add_task(notify_by_email, emails, f"New bill: {charge['name']} — {period}", branded_email(
            "You have a new estate bill",
            f"<p><strong>{html.escape(charge['name'])}</strong> for {html.escape(period)} is now due "
            f"(by {due.strftime('%d %b %Y')}).</p>{bank}"
            f"<p style='margin:20px 0;'><a href=\"{FRONTEND_URL}/app/payments\" style=\"background:#1e2a5e;color:#ffffff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;\">View my bills</a></p>"))
    return {"issued": issued, "skipped": skipped}


@app.get("/api/invoices")
async def list_invoices(status: Optional[str] = None, unit_id: Optional[str] = None, period: Optional[str] = None,
                        current_user: Dict = Depends(require_money_member)):
    estate_id = _estate_oid(current_user)
    q: Dict = {"estate_id": estate_id}
    if _is_admin(current_user):
        if unit_id:
            q["unit_id"] = _oid(unit_id, "unit")
    else:
        my_units = [u["_id"] for u in units_collection.find({"estate_id": estate_id, "$or": [
            {"occupant_user_ids": current_user["_id"]}, {"payer_user_id": current_user["_id"]}]}, {"_id": 1})]
        q["unit_id"] = {"$in": my_units}
    if status == "open":
        q["status"] = {"$in": ["unpaid", "part_paid"]}
    elif status:
        q["status"] = status
    if period:
        q["period"] = period
    now = datetime.utcnow()
    out = []
    for inv in invoices_collection.find(q).sort("due_date", -1).limit(500):
        d = serialize_doc(inv)
        d["balance"] = int(inv["amount"]) - int(inv.get("amount_paid", 0))
        d["overdue"] = inv["status"] in ("unpaid", "part_paid") and inv.get("due_date") and inv["due_date"] < now
        out.append(d)
    return out


@app.post("/api/invoices/{invoice_id}/void")
async def void_invoice(invoice_id: str, current_user: Dict = Depends(require_admin)):
    inv = invoices_collection.find_one({"_id": _oid(invoice_id, "bill"), "estate_id": _estate_oid(current_user)})
    if not inv:
        raise HTTPException(status_code=404, detail="Bill not found")
    if int(inv.get("amount_paid", 0)) > 0:
        raise HTTPException(status_code=400, detail="This bill already has payments on it. Record a refund instead of cancelling.")
    invoices_collection.update_one({"_id": inv["_id"]}, {"$set": {"status": "void", "voided_by": current_user["_id"], "voided_at": datetime.utcnow()}})
    return {"message": "Bill cancelled"}


# ---------------- payments ----------------
class PaymentCreate(BaseModel):
    amount: int = Field(..., gt=0)
    method: str = "bank_transfer"
    reference: Optional[str] = Field(None, max_length=80)
    invoice_id: Optional[str] = None
    unit_id: Optional[str] = None  # admin recording for a unit
    proof_image: Optional[str] = None
    note: Optional[str] = Field(None, max_length=300)

    @field_validator("method")
    @classmethod
    def _m(cls, v):
        if v not in PAYMENT_METHODS:
            raise ValueError("Unknown payment method")
        return v

    @field_validator("proof_image")
    @classmethod
    def _p(cls, v):
        if v and (len(v) > MAX_PROOF_CHARS or not v.startswith("data:image/")):
            raise ValueError("Receipt must be an image under about 1MB")
        return v


class PaymentDecision(BaseModel):
    reason: Optional[str] = Field(None, max_length=300)


def _confirm_payment(payment: Dict, admin: Dict, background_tasks: Optional[BackgroundTasks] = None) -> Dict:
    result = _apply_to_unit(payment["unit_id"], int(payment["amount"]), payment.get("invoice_id"))
    payments_collection.update_one({"_id": payment["_id"]}, {"$set": {
        "status": "confirmed", "confirmed_by": admin["_id"], "confirmed_at": datetime.utcnow(),
        "allocation": result["applied"], "to_credit": result["to_credit"]}})
    audit_logs_collection.insert_one({"user_id": admin["_id"], "estate_id": payment["estate_id"], "action": "confirm_payment",
                                      "entity": "payment", "entity_id": str(payment["_id"]),
                                      "details": {"amount": payment["amount"], "unit": payment.get("unit_label")}, "timestamp": datetime.utcnow()})
    payer = users_collection.find_one({"_id": payment.get("payer_user_id")}, {"email": 1, "name": 1}) if payment.get("payer_user_id") else None
    if background_tasks and payer and payer.get("email"):
        extra = f"<p>{_naira(result['to_credit'])} was added to your estate balance for future bills.</p>" if result["to_credit"] else ""
        background_tasks.add_task(send_email, payer["email"], f"Payment received: {_naira(payment['amount'])}", branded_email(
            "Payment confirmed",
            f"<p>Hi {html.escape((payer.get('name') or '').split(' ')[0])},</p>"
            f"<p>Your estate confirmed your payment of <strong>{_naira(payment['amount'])}</strong> for {html.escape(payment.get('unit_label') or 'your unit')}.</p>{extra}"
            f"<p>You can see your receipt and balance under Bills in NexHood.</p>"))
    return result


@app.post("/api/payments")
async def create_payment(body: PaymentCreate, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_money_member)):
    """Resident: "I've paid" (bank transfer/cash) with a receipt photo. It
    waits for an admin to confirm the money arrived. Admin: records a
    payment they received for a unit; it's confirmed straight away."""
    estate_id = _estate_oid(current_user)
    invoice = None
    if body.invoice_id:
        invoice = invoices_collection.find_one({"_id": _oid(body.invoice_id, "bill"), "estate_id": estate_id})
        if not invoice:
            raise HTTPException(status_code=404, detail="Bill not found")
    if _is_admin(current_user):
        unit_oid = invoice["unit_id"] if invoice else _oid(body.unit_id, "unit")
        unit = units_collection.find_one({"_id": unit_oid, "estate_id": estate_id})
    else:
        mine = {"estate_id": estate_id, "$or": [{"occupant_user_ids": current_user["_id"]}, {"payer_user_id": current_user["_id"]}]}
        unit = units_collection.find_one({**mine, "_id": invoice["unit_id"]}) if invoice else units_collection.find_one(mine)
        if body.method == "paystack":
            raise HTTPException(status_code=400, detail="Online payment isn't available yet")
        if not body.proof_image and not body.reference:
            raise HTTPException(status_code=400, detail="Add the transfer reference or a photo of your receipt")
    if not unit:
        raise HTTPException(status_code=404, detail="Your house/flat isn't set up yet. Ask your estate admin to add it.")
    doc = {"estate_id": estate_id, "unit_id": unit["_id"], "unit_label": unit["label"],
           "invoice_id": invoice["_id"] if invoice else None, "payer_user_id": current_user["_id"] if not _is_admin(current_user) else unit.get("payer_user_id"),
           "payer_name": current_user.get("name") if not _is_admin(current_user) else None,
           "amount": int(body.amount), "method": body.method, "reference": body.reference, "note": body.note,
           "proof_image": body.proof_image, "status": "pending", "recorded_by": current_user["_id"], "created_at": datetime.utcnow()}
    res = payments_collection.insert_one(doc)
    doc["_id"] = res.inserted_id
    if _is_admin(current_user):
        _confirm_payment(doc, current_user, background_tasks)
    else:
        admins = [a["email"] for a in users_collection.find({"estate_id": estate_id, "role": "admin", "is_active": True}, {"email": 1}) if a.get("email")]
        background_tasks.add_task(notify_by_email, admins, f"Payment to confirm: {_naira(body.amount)} from {unit['label']}", branded_email(
            "A resident says they've paid",
            f"<p><strong>{html.escape(current_user.get('name') or 'A resident')}</strong> ({html.escape(unit['label'])}) reported paying "
            f"<strong>{_naira(body.amount)}</strong> by {body.method.replace('_', ' ')}"
            f"{' (ref ' + html.escape(body.reference) + ')' if body.reference else ''}.</p>"
            f"<p>Check your bank, then confirm it in NexHood under Bills → Payments to confirm.</p>"))
    return serialize_doc({k: v for k, v in payments_collection.find_one({"_id": res.inserted_id}).items() if k != "proof_image"})


@app.get("/api/payments")
async def list_payments(status: Optional[str] = None, current_user: Dict = Depends(require_money_member)):
    q: Dict = {"estate_id": _estate_oid(current_user)}
    if not _is_admin(current_user):
        q["payer_user_id"] = current_user["_id"]
    if status:
        q["status"] = status
    else:
        # Unfinished online checkouts (resident closed the Paystack page) aren't payments.
        q["status"] = {"$nin": ["initiated", "confirming"]}
    out = []
    for p in payments_collection.find(q, {"proof_image": 0}).sort("created_at", -1).limit(300):
        d = serialize_doc(p)
        d["has_proof"] = bool(payments_collection.count_documents({"_id": p["_id"], "proof_image": {"$nin": [None, ""]}}))
        out.append(d)
    return out


@app.get("/api/payments/{payment_id}/proof")
async def get_payment_proof(payment_id: str, current_user: Dict = Depends(require_money_member)):
    p = payments_collection.find_one({"_id": _oid(payment_id, "payment"), "estate_id": _estate_oid(current_user)}, {"proof_image": 1, "payer_user_id": 1})
    if not p or (not _is_admin(current_user) and p.get("payer_user_id") != current_user["_id"]):
        raise HTTPException(status_code=404, detail="Payment not found")
    return {"proof_image": p.get("proof_image")}


@app.post("/api/payments/{payment_id}/confirm")
async def confirm_payment(payment_id: str, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_admin)):
    p = payments_collection.find_one({"_id": _oid(payment_id, "payment"), "estate_id": _estate_oid(current_user)})
    if not p:
        raise HTTPException(status_code=404, detail="Payment not found")
    if p["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"This payment is already {p['status']}")
    result = _confirm_payment(p, current_user, background_tasks)
    return {"message": "Payment confirmed", **serialize_doc(result)}


@app.post("/api/payments/{payment_id}/reject")
async def reject_payment(payment_id: str, body: PaymentDecision, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_admin)):
    p = payments_collection.find_one({"_id": _oid(payment_id, "payment"), "estate_id": _estate_oid(current_user)})
    if not p or p["status"] != "pending":
        raise HTTPException(status_code=404, detail="Pending payment not found")
    payments_collection.update_one({"_id": p["_id"]}, {"$set": {"status": "rejected", "rejected_by": current_user["_id"],
                                                                "rejected_at": datetime.utcnow(), "reject_reason": body.reason}})
    payer = users_collection.find_one({"_id": p.get("payer_user_id")}, {"email": 1}) if p.get("payer_user_id") else None
    if payer and payer.get("email"):
        background_tasks.add_task(send_email, payer["email"], "We couldn't confirm your payment", branded_email(
            "Payment not confirmed",
            f"<p>Your estate couldn't confirm your payment of {_naira(p['amount'])}.</p>"
            f"<p>{html.escape(body.reason or 'Please contact your estate admin.')}</p>"))
    return {"message": "Payment marked as not received"}


# ---------------- expenses (with approver for big amounts) ----------------
class ExpenseCreate(BaseModel):
    category: str
    amount: int = Field(..., gt=0)
    vendor: Optional[str] = Field(None, max_length=100)
    description: str = Field(..., min_length=3, max_length=500)
    date: datetime
    receipt_image: Optional[str] = None
    request_id: Optional[str] = None

    @field_validator("category")
    @classmethod
    def _c(cls, v):
        if v not in EXPENSE_CATEGORIES:
            raise ValueError("Unknown expense category")
        return v

    @field_validator("receipt_image")
    @classmethod
    def _r(cls, v):
        if v and (len(v) > MAX_PROOF_CHARS or not v.startswith("data:image/")):
            raise ValueError("Receipt must be an image under about 1MB")
        return v


def _approver_for(estate_id: ObjectId) -> Optional[ObjectId]:
    return _finance_settings(estate_id).get("approver_user_id")


@app.post("/api/expenses")
async def create_expense(body: ExpenseCreate, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_admin)):
    """Spending from estate funds. Anything at or above the estate's
    approval threshold waits for the named approver before it counts in
    the statement. Expenses are never deleted: a mistake is voided, and the
    void stays visible."""
    estate_id = _estate_oid(current_user)
    fin = _finance_settings(estate_id)
    threshold = int(fin.get("approval_threshold", 100000))
    approver = fin.get("approver_user_id")
    d = body.date if body.date.tzinfo is None else (body.date - body.date.utcoffset()).replace(tzinfo=None)
    needs_approval = body.amount >= threshold
    self_approved = needs_approval and approver == current_user["_id"]
    status = "approved" if (not needs_approval or self_approved) else "pending_approval"
    linked_request = None
    if body.request_id:
        linked_request = requests_collection.find_one({"_id": _oid(body.request_id, "request"), "estate_id": estate_id})
    doc = {"estate_id": estate_id, "category": body.category, "amount": int(body.amount), "vendor": body.vendor,
           "description": body.description.strip(), "date": d, "receipt_image": body.receipt_image,
           "request_id": linked_request["_id"] if linked_request else None, "request_title": (linked_request or {}).get("title"),
           "status": status, "self_approved": self_approved, "created_by": current_user["_id"], "created_by_name": current_user.get("name"),
           "created_at": datetime.utcnow(),
           **({"approved_by": current_user["_id"], "approved_at": datetime.utcnow()} if status == "approved" else {})}
    res = expenses_collection.insert_one(doc)
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": estate_id, "action": "create", "entity": "expense",
                                      "entity_id": str(res.inserted_id), "details": {"amount": doc["amount"], "category": doc["category"], "status": status},
                                      "timestamp": datetime.utcnow()})
    if status == "pending_approval":
        target = approver or None
        emails = []
        if target:
            a = users_collection.find_one({"_id": target}, {"email": 1})
            emails = [a["email"]] if a and a.get("email") else []
        else:
            emails = [a["email"] for a in users_collection.find({"estate_id": estate_id, "role": "admin", "is_active": True, "_id": {"$ne": current_user["_id"]}}, {"email": 1}) if a.get("email")]
        background_tasks.add_task(notify_by_email, emails, f"Approve spending: {_naira(body.amount)}", branded_email(
            "An expense needs your approval",
            f"<p>{html.escape(current_user.get('name') or 'An admin')} recorded <strong>{_naira(body.amount)}</strong> for "
            f"{html.escape(CATEGORY_LABEL.get(body.category, body.category))}: {html.escape(body.description)}.</p>"
            f"<p>It won't appear in the estate statement until you approve it in NexHood under Estate finances.</p>"))
    return serialize_doc({k: v for k, v in doc.items() if k != "receipt_image"} | {"_id": res.inserted_id, "has_receipt": bool(body.receipt_image)})


@app.get("/api/expenses")
async def list_expenses(month: Optional[str] = None, status: Optional[str] = None, current_user: Dict = Depends(require_money_member)):
    estate_id = _estate_oid(current_user)
    q: Dict = {"estate_id": estate_id}
    if not _is_admin(current_user):
        q["status"] = {"$in": ["approved", "void"]}
    elif status:
        q["status"] = status
    if month:
        try:
            start = datetime.strptime(month, "%Y-%m")
        except ValueError:
            raise HTTPException(status_code=400, detail="Month must look like 2026-10")
        end = (start + timedelta(days=32)).replace(day=1)
        q["date"] = {"$gte": start, "$lt": end}
    out = []
    for e in expenses_collection.find(q, {"receipt_image": 0}).sort("date", -1).limit(500):
        d = serialize_doc(e)
        d["has_receipt"] = bool(expenses_collection.count_documents({"_id": e["_id"], "receipt_image": {"$nin": [None, ""]}}))
        out.append(d)
    return out


@app.get("/api/expenses/{expense_id}/receipt")
async def get_expense_receipt(expense_id: str, current_user: Dict = Depends(require_money_member)):
    e = expenses_collection.find_one({"_id": _oid(expense_id, "expense"), "estate_id": _estate_oid(current_user)}, {"receipt_image": 1, "status": 1})
    if not e or (not _is_admin(current_user) and e.get("status") not in ("approved", "void")):
        raise HTTPException(status_code=404, detail="Expense not found")
    return {"receipt_image": e.get("receipt_image")}


@app.post("/api/expenses/{expense_id}/approve")
async def approve_expense(expense_id: str, current_user: Dict = Depends(require_admin)):
    estate_id = _estate_oid(current_user)
    e = expenses_collection.find_one({"_id": _oid(expense_id, "expense"), "estate_id": estate_id})
    if not e or e["status"] != "pending_approval":
        raise HTTPException(status_code=404, detail="Nothing waiting for approval here")
    approver = _approver_for(estate_id)
    if approver and approver != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Only the estate's finance approver can approve this")
    if not approver and e.get("created_by") == current_user["_id"]:
        raise HTTPException(status_code=403, detail="Another admin has to approve spending you recorded. Or set a finance approver in Settings.")
    expenses_collection.update_one({"_id": e["_id"]}, {"$set": {"status": "approved", "approved_by": current_user["_id"],
                                                                "approved_by_name": current_user.get("name"), "approved_at": datetime.utcnow()}})
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": estate_id, "action": "approve", "entity": "expense",
                                      "entity_id": str(e["_id"]), "details": {"amount": e["amount"]}, "timestamp": datetime.utcnow()})
    return {"message": "Approved"}


@app.post("/api/expenses/{expense_id}/reject")
async def reject_expense(expense_id: str, body: PaymentDecision, current_user: Dict = Depends(require_admin)):
    estate_id = _estate_oid(current_user)
    e = expenses_collection.find_one({"_id": _oid(expense_id, "expense"), "estate_id": estate_id})
    if not e or e["status"] != "pending_approval":
        raise HTTPException(status_code=404, detail="Nothing waiting for approval here")
    approver = _approver_for(estate_id)
    if approver and approver != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Only the estate's finance approver can decide this")
    expenses_collection.update_one({"_id": e["_id"]}, {"$set": {"status": "rejected", "rejected_by": current_user["_id"],
                                                                "reject_reason": body.reason, "rejected_at": datetime.utcnow()}})
    return {"message": "Rejected"}


@app.post("/api/expenses/{expense_id}/void")
async def void_expense(expense_id: str, body: PaymentDecision, current_user: Dict = Depends(require_admin)):
    e = expenses_collection.find_one({"_id": _oid(expense_id, "expense"), "estate_id": _estate_oid(current_user)})
    if not e or e["status"] not in ("approved", "pending_approval"):
        raise HTTPException(status_code=404, detail="Expense not found")
    if not (body.reason or "").strip():
        raise HTTPException(status_code=400, detail="Say why it's being voided. Residents will see it.")
    expenses_collection.update_one({"_id": e["_id"]}, {"$set": {"status": "void", "voided_by": current_user["_id"],
                                                                "void_reason": body.reason.strip(), "voided_at": datetime.utcnow()}})
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": e["estate_id"], "action": "void", "entity": "expense",
                                      "entity_id": str(e["_id"]), "details": {"amount": e["amount"], "reason": body.reason}, "timestamp": datetime.utcnow()})
    return {"message": "Expense voided"}


# ---------------- statement & summaries ----------------
def _sum(coll, match: Dict, field: str) -> int:
    agg = list(coll.aggregate([{"$match": match}, {"$group": {"_id": None, "t": {"$sum": f"${field}"}}}]))
    return int(agg[0]["t"]) if agg else 0


@app.get("/api/finance/statement")
async def finance_statement(month: Optional[str] = None, current_user: Dict = Depends(require_money_member)):
    """The monthly "where the money went" statement every resident can see."""
    estate_id = _estate_oid(current_user)
    now = datetime.utcnow()
    try:
        start = datetime.strptime(month, "%Y-%m") if month else datetime(now.year, now.month, 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Month must look like 2026-10")
    end = (start + timedelta(days=32)).replace(day=1)
    paid_before = _sum(payments_collection, {"estate_id": estate_id, "status": "confirmed", "confirmed_at": {"$lt": start}}, "amount")
    spent_before = _sum(expenses_collection, {"estate_id": estate_id, "status": "approved", "date": {"$lt": start}}, "amount")
    collected = _sum(payments_collection, {"estate_id": estate_id, "status": "confirmed", "confirmed_at": {"$gte": start, "$lt": end}}, "amount")
    by_cat = list(expenses_collection.aggregate([
        {"$match": {"estate_id": estate_id, "status": "approved", "date": {"$gte": start, "$lt": end}}},
        {"$group": {"_id": "$category", "total": {"$sum": "$amount"}, "count": {"$sum": 1}}},
        {"$sort": {"total": -1}},
    ]))
    spent = sum(int(c["total"]) for c in by_cat)
    opening = paid_before - spent_before
    billed = _sum(invoices_collection, {"estate_id": estate_id, "status": {"$ne": "void"}, "due_date": {"$gte": start, "$lt": end}}, "amount")
    billed_paid = _sum(invoices_collection, {"estate_id": estate_id, "status": {"$ne": "void"}, "due_date": {"$gte": start, "$lt": end}}, "amount_paid")
    outstanding = _sum(invoices_collection, {"estate_id": estate_id, "status": {"$in": ["unpaid", "part_paid"]}}, "amount") - \
        _sum(invoices_collection, {"estate_id": estate_id, "status": {"$in": ["unpaid", "part_paid"]}}, "amount_paid")
    units_total = units_collection.count_documents({"estate_id": estate_id, "active": True})
    units_owing = len(invoices_collection.distinct("unit_id", {"estate_id": estate_id, "status": {"$in": ["unpaid", "part_paid"]}}))
    return {
        "month": start.strftime("%Y-%m"),
        "opening_balance": opening,
        "collected": collected,
        "spent": spent,
        "closing_balance": opening + collected - spent,
        "spending": [{"category": c["_id"], "label": CATEGORY_LABEL.get(c["_id"], c["_id"]), "total": int(c["total"]), "count": c["count"]} for c in by_cat],
        "billed_this_month": billed,
        "collection_rate_pct": round(billed_paid / billed * 100) if billed else None,
        "outstanding_total": max(outstanding, 0),
        "units_total": units_total,
        "units_owing": units_owing,
        "pending_approval": expenses_collection.count_documents({"estate_id": estate_id, "status": "pending_approval"}) if _is_admin(current_user) else None,
    }


@app.get("/api/finance/arrears")
async def finance_arrears(current_user: Dict = Depends(require_admin)):
    estate_id = _estate_oid(current_user)
    rows = list(invoices_collection.aggregate([
        {"$match": {"estate_id": estate_id, "status": {"$in": ["unpaid", "part_paid"]}}},
        {"$group": {"_id": "$unit_id", "label": {"$first": "$unit_label"}, "due": {"$sum": {"$subtract": ["$amount", "$amount_paid"]}},
                    "bills": {"$sum": 1}, "oldest": {"$min": "$due_date"}}},
        {"$sort": {"due": -1}},
    ]))
    return [serialize_doc({"unit_id": r["_id"], "label": r["label"], "due": int(r["due"]), "bills": r["bills"], "oldest_due": r["oldest"]}) for r in rows]


@app.get("/api/finance/me")
async def finance_me(current_user: Dict = Depends(require_money_member)):
    estate_id = _estate_oid(current_user)
    units = list(units_collection.find({"estate_id": estate_id, "$or": [{"occupant_user_ids": current_user["_id"]}, {"payer_user_id": current_user["_id"]}]}))
    fin = _finance_settings(estate_id)
    return {
        "units": [{"id": str(u["_id"]), "label": u["label"], "credit": int(u.get("credit", 0)), "balance_due": _unit_balance(u["_id"]),
                   "is_payer": u.get("payer_user_id") == current_user["_id"]} for u in units],
        "bank": {"bank_name": fin.get("bank_name"), "account_name": fin.get("account_name"), "account_number": fin.get("account_number")},
        "pending_payments": payments_collection.count_documents({"estate_id": estate_id, "payer_user_id": current_user["_id"], "status": "pending"}),
    }


# ---------------- facility (repair) requests ----------------
class RepairCreate(BaseModel):
    category: str
    title: str = Field(..., min_length=3, max_length=120)
    description: str = Field(..., min_length=5, max_length=2000)
    location: Optional[str] = Field(None, max_length=120)
    visibility: str = "estate"
    images: Optional[List[str]] = Field(None, max_length=3)

    @field_validator("category")
    @classmethod
    def _c(cls, v):
        if v not in REQUEST_CATEGORIES:
            raise ValueError("Unknown category")
        return v

    @field_validator("visibility")
    @classmethod
    def _v(cls, v):
        if v not in ("estate", "management"):
            raise ValueError("Visibility must be estate or management")
        return v

    @field_validator("images")
    @classmethod
    def _i(cls, v):
        if v and sum(len(i) for i in v) > 4 * 1024 * 1024:
            raise ValueError("Photos are too large")
        return v


class RepairUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = Field(None, max_length=100)
    note: Optional[str] = Field(None, max_length=500)

    @field_validator("status")
    @classmethod
    def _s(cls, v):
        if v is not None and v not in REQUEST_STATUSES:
            raise ValueError("Unknown status")
        return v


def _repair_out(r: Dict, me: Dict) -> Dict:
    d = serialize_doc({k: v for k, v in r.items() if k != "me_too"})
    d["me_too_count"] = len(r.get("me_too") or [])
    d["me_too_mine"] = me["_id"] in (r.get("me_too") or [])
    d["mine"] = r.get("reporter_id") == me["_id"]
    spent = list(expenses_collection.find({"request_id": r["_id"], "status": "approved"}, {"amount": 1}))
    d["cost"] = sum(int(e["amount"]) for e in spent) if spent else None
    return d


@app.post("/api/repairs")
async def create_repair(body: RepairCreate, background_tasks: BackgroundTasks, current_user: Dict = Depends(get_current_user)):
    estate_id = _estate_oid(current_user)
    doc = {**body.dict(), "image_count": len(body.images or []), "estate_id": estate_id, "status": "reported", "reporter_id": current_user["_id"],
           "reporter_name": current_user.get("name"), "reporter_unit": current_user.get("apartment"),
           "me_too": [], "updates": [], "created_at": datetime.utcnow()}
    res = requests_collection.insert_one(doc)
    doc["_id"] = res.inserted_id
    admins = [a["email"] for a in users_collection.find({"estate_id": estate_id, "role": "admin", "is_active": True}, {"email": 1}) if a.get("email")]
    background_tasks.add_task(notify_by_email, admins, f"New repair request: {body.title}", branded_email(
        "New repair request",
        f"<p><strong>{html.escape(body.title)}</strong> ({html.escape(body.category.replace('_', ' '))})"
        f"{' at ' + html.escape(body.location) if body.location else ''}</p><p>{html.escape(body.description)}</p>"
        f"<p>Reported by {html.escape(current_user.get('name') or 'a resident')}.</p>"))
    return _repair_out(doc, current_user)


@app.get("/api/repairs")
async def list_repairs(status: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    estate_id = _estate_oid(current_user)
    q: Dict = {"estate_id": estate_id}
    if not _is_admin(current_user) and current_user.get("role") != "guard":
        q["$or"] = [{"visibility": "estate"}, {"reporter_id": current_user["_id"]}]
    if status == "open":
        q["status"] = {"$in": ["reported", "assigned", "in_progress"]}
    elif status:
        q["status"] = status
    return [_repair_out(r, current_user) for r in requests_collection.find(q, {"images": 0}).sort("created_at", -1).limit(200)]


@app.get("/api/repairs/{repair_id}")
async def get_repair(repair_id: str, current_user: Dict = Depends(get_current_user)):
    r = requests_collection.find_one({"_id": _oid(repair_id, "request"), "estate_id": _estate_oid(current_user)})
    if not r or (r.get("visibility") == "management" and not _is_admin(current_user) and current_user.get("role") != "guard" and r.get("reporter_id") != current_user["_id"]):
        raise HTTPException(status_code=404, detail="Request not found")
    return _repair_out(r, current_user)


@app.post("/api/repairs/{repair_id}/me-too")
async def repair_me_too(repair_id: str, current_user: Dict = Depends(get_current_user)):
    r = requests_collection.find_one({"_id": _oid(repair_id, "request"), "estate_id": _estate_oid(current_user), "visibility": "estate"})
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    if current_user["_id"] in (r.get("me_too") or []):
        requests_collection.update_one({"_id": r["_id"]}, {"$pull": {"me_too": current_user["_id"]}})
    else:
        requests_collection.update_one({"_id": r["_id"]}, {"$addToSet": {"me_too": current_user["_id"]}})
    return _repair_out(requests_collection.find_one({"_id": r["_id"]}, {"images": 0}), current_user)


@app.patch("/api/repairs/{repair_id}")
async def update_repair(repair_id: str, body: RepairUpdate, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_admin)):
    r = requests_collection.find_one({"_id": _oid(repair_id, "request"), "estate_id": _estate_oid(current_user)})
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    changes: Dict = {}
    if body.status:
        changes["status"] = body.status
        if body.status in ("fixed", "closed"):
            changes["fixed_at"] = datetime.utcnow()
    if body.assigned_to is not None:
        changes["assigned_to"] = body.assigned_to.strip() or None
    update = {"$set": changes} if changes else {}
    if body.note or body.status:
        update["$push"] = {"updates": {"by": current_user.get("name"), "status": body.status, "note": body.note, "at": datetime.utcnow()}}
    if not update:
        raise HTTPException(status_code=400, detail="Nothing to update")
    requests_collection.update_one({"_id": r["_id"]}, update)
    if body.status in ("fixed", "closed"):
        people = [r.get("reporter_id")] + list(r.get("me_too") or [])
        emails = [u["email"] for u in users_collection.find({"_id": {"$in": [p for p in people if p]}}, {"email": 1}) if u.get("email")]
        background_tasks.add_task(notify_by_email, emails, f"Fixed: {r['title']}", branded_email(
            "A repair you reported was fixed",
            f"<p><strong>{html.escape(r['title'])}</strong> is marked as {body.status}.</p>"
            f"{'<p>' + html.escape(body.note) + '</p>' if body.note else ''}"))
    return _repair_out(requests_collection.find_one({"_id": r["_id"]}, {"images": 0}), current_user)


@app.get("/api/repairs/{repair_id}/images")
async def get_repair_images(repair_id: str, current_user: Dict = Depends(get_current_user)):
    r = requests_collection.find_one({"_id": _oid(repair_id, "request"), "estate_id": _estate_oid(current_user)}, {"images": 1, "visibility": 1, "reporter_id": 1})
    if not r or (r.get("visibility") == "management" and not _is_admin(current_user) and current_user.get("role") != "guard" and r.get("reporter_id") != current_user["_id"]):
        raise HTTPException(status_code=404, detail="Request not found")
    return {"images": r.get("images") or []}


# ===========================================================================
# ONLINE PAYMENTS (Paystack) — dormant until PAYSTACK_SECRET_KEY is set.
#
# How the money moves:
#   resident pays (bill + convenience fee) on Paystack's checkout
#     -> Paystack splits it: the bill amount settles to the ESTATE's own bank
#        account (its Paystack subaccount); the convenience fee goes to
#        NexHood's main Paystack balance, which also pays Paystack's charge.
#     -> Paystack calls our webhook; we mark the bill paid automatically.
# NexHood never holds the estate's money.
# ===========================================================================
import hmac
import hashlib
import urllib.request
import urllib.error
import urllib.parse

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_ENABLED = bool(PAYSTACK_SECRET_KEY)
# NexHood's margin per online payment, on top of covering Paystack's own fee.
NEXHOOD_FEE_MARGIN = int(os.getenv("NEXHOOD_FEE_MARGIN", "100"))
_bank_cache: Dict = {}


def _paystack(method: str, path: str, body: Optional[Dict] = None) -> Dict:
    if not PAYSTACK_ENABLED:
        raise HTTPException(status_code=503, detail="Online payments aren't switched on yet")
    req = urllib.request.Request(
        f"https://api.paystack.co{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode()).get("message")
        except Exception:
            msg = None
        logger.error(f"Paystack {method} {path} failed: {e.code} {msg}")
        raise HTTPException(status_code=400, detail=msg or "Paystack rejected the request")
    except Exception as e:
        logger.error(f"Paystack {method} {path} error: {e}")
        raise HTTPException(status_code=502, detail="Couldn't reach Paystack. Please try again.")


def paystack_fee(total_naira: int) -> int:
    """Paystack Nigeria local fee: 1.5% + N100 (the N100 is waived under
    N2,500), capped at N2,000."""
    fee = total_naira * 0.015 + (100 if total_naira >= 2500 else 0)
    return int(min(-(-fee // 1), 2000))


def convenience_fee(bill_naira: int) -> int:
    """What the resident pays on top of the bill so the estate receives the
    full bill amount: Paystack's fee on the total + NexHood's margin."""
    fee = NEXHOOD_FEE_MARGIN
    for _ in range(5):  # converge: the Paystack fee depends on the total
        fee = paystack_fee(bill_naira + fee) + NEXHOOD_FEE_MARGIN
    return fee


@app.get("/api/finance/paystack/status")
async def paystack_status(current_user: Dict = Depends(require_money_member)):
    fin = _finance_settings(_estate_oid(current_user))
    return {
        "enabled": PAYSTACK_ENABLED,
        "connected": bool(fin.get("paystack_subaccount_code")),
        "settlement": {"bank_name": fin.get("paystack_bank_name"), "account_name": fin.get("paystack_account_name"),
                       "account_number": fin.get("paystack_account_number")} if fin.get("paystack_subaccount_code") else None,
        "fee_margin": NEXHOOD_FEE_MARGIN,
    }


@app.get("/api/finance/paystack/banks")
async def paystack_banks(current_user: Dict = Depends(require_admin)):
    if "ng" not in _bank_cache:
        data = await asyncio.to_thread(_paystack, "GET", "/bank?country=nigeria&perPage=200")
        _bank_cache["ng"] = sorted([{"name": b["name"], "code": b["code"]} for b in data.get("data", []) if b.get("active", True)], key=lambda b: b["name"])
    return _bank_cache["ng"]


class PaystackConnect(BaseModel):
    bank_code: str = Field(..., min_length=2, max_length=10)
    account_number: str = Field(..., min_length=10, max_length=10)


@app.post("/api/finance/paystack/connect")
async def paystack_connect(body: PaystackConnect, current_user: Dict = Depends(require_admin)):
    """Link the estate's bank account to NexHood's Paystack as a subaccount.
    Online payments for this estate then settle straight into it."""
    estate_id = _estate_oid(current_user)
    estate = estates_collection.find_one({"_id": estate_id}, {"name": 1})
    resolved = await asyncio.to_thread(_paystack, "GET", f"/bank/resolve?account_number={urllib.parse.quote(body.account_number)}&bank_code={urllib.parse.quote(body.bank_code)}")
    account_name = (resolved.get("data") or {}).get("account_name")
    if not account_name:
        raise HTTPException(status_code=400, detail="We couldn't find that account. Check the number and bank.")
    banks = {b["code"]: b["name"] for b in await paystack_banks(current_user)}
    sub = await asyncio.to_thread(_paystack, "POST", "/subaccount", {
        "business_name": (estate or {}).get("name", "Estate")[:100],
        "settlement_bank": body.bank_code,
        "account_number": body.account_number,
        "percentage_charge": 0,
        "description": "NexHood estate collections",
    })
    code = (sub.get("data") or {}).get("subaccount_code")
    if not code:
        raise HTTPException(status_code=400, detail="Paystack didn't create the payout account")
    estates_collection.update_one({"_id": estate_id}, {"$set": {
        "finance.paystack_subaccount_code": code,
        "finance.paystack_bank_name": banks.get(body.bank_code),
        "finance.paystack_account_name": account_name,
        "finance.paystack_account_number": body.account_number,
    }})
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": estate_id, "action": "update_finance_settings",
                                      "entity": "estate", "details": {"paystack": "connected", "account_name": account_name}, "timestamp": datetime.utcnow()})
    return await paystack_status(current_user)


class PaystackInit(BaseModel):
    amount: int = Field(..., gt=0)
    invoice_id: Optional[str] = None


@app.get("/api/payments/paystack/quote")
async def paystack_quote(amount: int, current_user: Dict = Depends(require_money_member)):
    fee = convenience_fee(int(amount))
    return {"amount": int(amount), "fee": fee, "total": int(amount) + fee}


@app.post("/api/payments/paystack/init")
async def paystack_init(body: PaystackInit, current_user: Dict = Depends(require_money_member)):
    estate_id = _estate_oid(current_user)
    fin = _finance_settings(estate_id)
    sub = fin.get("paystack_subaccount_code")
    if not PAYSTACK_ENABLED or not sub:
        raise HTTPException(status_code=400, detail="Online payment isn't set up for your estate yet. Pay by transfer for now.")
    mine = {"estate_id": estate_id, "$or": [{"occupant_user_ids": current_user["_id"]}, {"payer_user_id": current_user["_id"]}]}
    invoice = None
    if body.invoice_id:
        invoice = invoices_collection.find_one({"_id": _oid(body.invoice_id, "bill"), "estate_id": estate_id})
        if not invoice:
            raise HTTPException(status_code=404, detail="Bill not found")
        unit = units_collection.find_one({**mine, "_id": invoice["unit_id"]})
    else:
        unit = units_collection.find_one(mine)
    if not unit:
        raise HTTPException(status_code=404, detail="Your house/flat isn't set up yet")
    fee = convenience_fee(body.amount)
    total = body.amount + fee
    reference = f"NXH-{secrets.token_hex(8).upper()}"
    payments_collection.insert_one({
        "estate_id": estate_id, "unit_id": unit["_id"], "unit_label": unit["label"],
        "invoice_id": invoice["_id"] if invoice else None, "payer_user_id": current_user["_id"], "payer_name": current_user.get("name"),
        "amount": int(body.amount), "fee": fee, "method": "paystack", "reference": reference, "status": "initiated",
        "recorded_by": current_user["_id"], "created_at": datetime.utcnow(),
    })
    data = await asyncio.to_thread(_paystack, "POST", "/transaction/initialize", {
        "email": current_user["email"],
        "amount": total * 100,            # kobo
        "reference": reference,
        "subaccount": sub,
        "transaction_charge": fee * 100,  # NexHood's share (kobo); the estate gets the rest
        "bearer": "account",              # NexHood's share pays Paystack's fee, so the estate gets the full bill
        "callback_url": f"{FRONTEND_URL}/app/payments?paystack=1",
        "metadata": {"estate_id": str(estate_id), "unit_id": str(unit["_id"]), "unit": unit["label"],
                     "invoice_id": str(invoice["_id"]) if invoice else None, "bill_amount": body.amount, "fee": fee},
    })
    url = (data.get("data") or {}).get("authorization_url")
    if not url:
        raise HTTPException(status_code=502, detail="Paystack didn't return a checkout link")
    return {"authorization_url": url, "reference": reference, "amount": body.amount, "fee": fee, "total": total}


SYSTEM_PAYSTACK_ACTOR = {"_id": None, "name": "Paystack"}


def _settle_paystack(reference: str, background_tasks: Optional[BackgroundTasks] = None) -> Dict:
    """Verify with Paystack and, if paid, apply it to the bills — exactly
    once, even if the webhook and the browser redirect both arrive."""
    pay = payments_collection.find_one({"reference": reference, "method": "paystack"})
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    if pay["status"] in ("confirmed", "failed"):
        return {"status": pay["status"]}
    data = (_paystack("GET", f"/transaction/verify/{urllib.parse.quote(reference)}").get("data") or {})
    if data.get("status") != "success":
        if data.get("status") in ("failed", "abandoned", "reversed"):
            payments_collection.update_one({"_id": pay["_id"], "status": "initiated"}, {"$set": {"status": "failed", "paystack_status": data.get("status")}})
            return {"status": "failed"}
        return {"status": "pending"}
    expected_kobo = (int(pay["amount"]) + int(pay.get("fee", 0))) * 100
    if int(data.get("amount", 0)) < expected_kobo:
        logger.error(f"Paystack amount mismatch for {reference}: got {data.get('amount')}, expected {expected_kobo}")
        payments_collection.update_one({"_id": pay["_id"]}, {"$set": {"status": "failed", "paystack_status": "amount_mismatch"}})
        return {"status": "failed"}
    # Claim it atomically so only one caller applies the money.
    claimed = payments_collection.find_one_and_update({"_id": pay["_id"], "status": "initiated"}, {"$set": {"status": "confirming"}})
    if not claimed:
        return {"status": payments_collection.find_one({"_id": pay["_id"]}, {"status": 1}).get("status")}
    claimed["status"] = "confirming"
    _confirm_payment(claimed, SYSTEM_PAYSTACK_ACTOR, background_tasks)
    payments_collection.update_one({"_id": pay["_id"]}, {"$set": {"paystack_paid_at": data.get("paid_at"), "channel": data.get("channel")}})
    return {"status": "confirmed"}


@app.get("/api/payments/paystack/verify")
async def paystack_verify(reference: str, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_money_member)):
    pay = payments_collection.find_one({"reference": reference, "estate_id": _estate_oid(current_user)}, {"_id": 1})
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    return await asyncio.to_thread(_settle_paystack, reference, background_tasks)


@app.post("/api/paystack/webhook")
async def paystack_webhook(request: Request, background_tasks: BackgroundTasks):
    """Paystack calls this when a payment succeeds. The signature proves it
    really came from Paystack; we still re-verify the transaction."""
    raw = await request.body()
    signature = request.headers.get("x-paystack-signature", "")
    if not PAYSTACK_ENABLED or not hmac.compare_digest(hmac.new(PAYSTACK_SECRET_KEY.encode(), raw, hashlib.sha512).hexdigest(), signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    try:
        event = json.loads(raw.decode())
    except Exception:
        return {"ok": True}
    if event.get("event") == "charge.success":
        ref = (event.get("data") or {}).get("reference")
        if ref and ref.startswith("NXH-"):
            try:
                await asyncio.to_thread(_settle_paystack, ref, background_tasks)
            except HTTPException as e:
                logger.error(f"Webhook settle failed for {ref}: {e.detail}")
    return {"ok": True}


# ===========================================================================
# RED DOTS: "what's new for me" counts per section of the app.
# Each user has a last-seen time per section; opening the page clears it.
# ===========================================================================
NOTIFY_SECTIONS = ("alerts", "incidents", "community", "payments", "finances", "repairs", "visitor_passes", "welfare")


def _seen(user: Dict, section: str) -> datetime:
    t = (user.get("seen") or {}).get(section)
    return t or max(user.get("created_at") or datetime.utcnow(), datetime.utcnow() - timedelta(days=7))


@app.get("/api/notifications/counts")
async def notification_counts(current_user: Dict = Depends(get_current_user)):
    estate_id = _estate_oid(current_user)
    me = current_user["_id"]
    role = current_user.get("role")
    admin = role in ("admin", "super_admin")
    staff = admin or role == "guard"
    my_units = [u["_id"] for u in units_collection.find({"estate_id": estate_id, "$or": [{"occupant_user_ids": me}, {"payer_user_id": me}]}, {"_id": 1})]
    out: Dict = {}
    urgent: Dict = {}

    # Alerts: new ones raised by others; for guards/admins, any still unanswered is urgent.
    out["alerts"] = alerts_collection.count_documents({"estate_id": estate_id, "sender_id": {"$ne": me}, "created_at": {"$gt": _seen(current_user, "alerts")}})
    if staff:
        urgent["alerts"] = alerts_collection.count_documents({"estate_id": estate_id, "status": "active"})

    out["incidents"] = incidents_collection.count_documents({"estate_id": estate_id, "reporter_id": {"$ne": me}, "created_at": {"$gt": _seen(current_user, "incidents")}})
    out["community"] = posts_collection.count_documents({"estate_id": estate_id, "author_id": {"$ne": me}, "created_at": {"$gt": _seen(current_user, "community")}})

    since_rep = _seen(current_user, "repairs")
    rq = {"estate_id": estate_id, "reporter_id": {"$ne": me}, "created_at": {"$gt": since_rep}}
    if not staff:
        rq["visibility"] = "estate"
    out["repairs"] = requests_collection.count_documents(rq) + requests_collection.count_documents(
        {"estate_id": estate_id, "reporter_id": me, "updates.at": {"$gt": since_rep}})

    money = role in ("resident", "admin", "super_admin")
    since_pay = _seen(current_user, "payments")
    if not money:
        pass  # guards and police never see bills, payments or the estate books
    elif admin:
        urgent["payments"] = payments_collection.count_documents({"estate_id": estate_id, "status": "pending"})
        out["payments"] = payments_collection.count_documents({"estate_id": estate_id, "status": "confirmed", "method": "paystack", "confirmed_at": {"$gt": since_pay}})
    else:
        out["payments"] = invoices_collection.count_documents({"unit_id": {"$in": my_units}, "created_at": {"$gt": since_pay}}) + \
            payments_collection.count_documents({"payer_user_id": me, "$or": [{"confirmed_at": {"$gt": since_pay}}, {"rejected_at": {"$gt": since_pay}}]})
        urgent["payments"] = invoices_collection.count_documents({"unit_id": {"$in": my_units}, "status": {"$in": ["unpaid", "part_paid"]}, "due_date": {"$lt": datetime.utcnow()}})

    if admin:
        approver = _finance_settings(estate_id).get("approver_user_id")
        q = {"estate_id": estate_id, "status": "pending_approval"}
        if approver:
            urgent["finances"] = expenses_collection.count_documents(q) if approver == me else 0
        else:
            urgent["finances"] = expenses_collection.count_documents({**q, "created_by": {"$ne": me}})
    if money:
        out["finances"] = expenses_collection.count_documents({"estate_id": estate_id, "status": "approved", "created_by": {"$ne": me},
                                                               "approved_at": {"$gt": _seen(current_user, "finances")}})

    since_vp = _seen(current_user, "visitor_passes")
    if role == "guard":
        out["visitor_passes"] = passes_collection.count_documents({"estate_id": estate_id, "created_at": {"$gt": since_vp}, "status": "active"})
    else:
        out["visitor_passes"] = passes_collection.count_documents({"estate_id": estate_id, "host_id": me, "used_at": {"$gt": since_vp}})

    out["welfare"] = campaigns_collection.count_documents({"estate_id": estate_id, "created_by": {"$ne": me}, "created_at": {"$gt": _seen(current_user, "welfare")}})
    if admin:
        urgent["welfare"] = donations_collection.count_documents({"estate_id": estate_id, "status": "pending"})

    return {"new": out, "urgent": urgent}


class SeenBody(BaseModel):
    section: str


@app.post("/api/notifications/seen")
async def notification_seen(body: SeenBody, current_user: Dict = Depends(get_current_user)):
    if body.section not in NOTIFY_SECTIONS:
        raise HTTPException(status_code=400, detail="Unknown section")
    users_collection.update_one({"_id": current_user["_id"]}, {"$set": {f"seen.{body.section}": datetime.utcnow()}})
    return {"ok": True}



# ---------------------------------------------------------------------------
# v32 (estate): bills setup checklist + payment reminders
# ---------------------------------------------------------------------------
@app.get("/api/finance/setup")
async def finance_setup(current_user: Dict = Depends(require_admin)):
    """One call that tells the admin what's left before residents can be billed."""
    estate_id = _estate_oid(current_user)
    fin = _finance_settings(estate_id)
    units = list(units_collection.find({"estate_id": estate_id, "active": True}, {"unit_type": 1, "label": 1}))
    priced_types = set()
    for c in charges_collection.find({"estate_id": estate_id, "active": True}, {"type_amounts": 1}):
        priced_types.update((c.get("type_amounts") or {}).keys())
    untyped = [u["label"] for u in units if priced_types and (u.get("unit_type") or "") not in priced_types]
    return {
        "bank": bool(fin.get("account_number")),
        "units": len(units),
        "units_untyped": len(untyped),
        "untyped_labels": untyped[:10],
        "price_types": sorted(priced_types),
        "charges": charges_collection.count_documents({"estate_id": estate_id, "active": True}),
        "invoices": invoices_collection.count_documents({"estate_id": estate_id, "status": {"$ne": "void"}}),
        "paystack": bool(fin.get("paystack_subaccount_code")),
        "approver": bool(fin.get("approver_user_id")),
    }


class RemindBody(BaseModel):
    unit_id: Optional[str] = None


@app.post("/api/finance/remind")
async def finance_remind(body: RemindBody, background_tasks: BackgroundTasks, current_user: Dict = Depends(require_admin)):
    """Email a polite reminder to whoever pays for each house that owes.
    One house (unit_id) or everyone who owes. A house is reminded at most
    once every 20 hours, so a double tap never spams anyone."""
    estate_id = _estate_oid(current_user)
    q: Dict = {"estate_id": estate_id, "active": True}
    if body.unit_id:
        q["_id"] = _oid(body.unit_id, "unit")
    estate = estates_collection.find_one({"_id": estate_id}, {"name": 1}) or {}
    fin = _finance_settings(estate_id)
    now = datetime.utcnow()
    sent = skipped = 0
    for u in units_collection.find(q):
        due = _unit_balance(u["_id"])
        if due <= 0:
            continue
        last = u.get("last_reminded_at")
        if last and (now - last) < timedelta(hours=20):
            skipped += 1
            continue
        emails = _unit_payer_emails(u)
        if not emails:
            skipped += 1
            continue
        bank = ""
        if fin.get("account_number"):
            bank = (f"<p>Pay by transfer to <strong>{html.escape(fin.get('account_name') or '')}</strong>, "
                    f"{html.escape(fin.get('bank_name') or '')}, <strong>{html.escape(fin.get('account_number'))}</strong>, "
                    f"then tap “I paid” in NexHood.</p>")
        body_html = (f"<p>Hello,</p><p>This is a friendly reminder that <strong>{html.escape(u.get('label') or 'your house')}</strong> "
                     f"has <strong>{_naira(due)}</strong> outstanding on estate bills at {html.escape(estate.get('name') or 'your estate')}.</p>"
                     + bank +
                     f"<p><a href=\"{FRONTEND_URL}/app/payments\">See your bills and pay in NexHood</a></p>"
                     f"<p>If you've already paid, please ignore this. Your admin will confirm it shortly.</p>")
        for e in emails[:2]:
            background_tasks.add_task(send_email, e, f"Reminder: {_naira(due)} due for {u.get('label') or 'your house'}",
                                      branded_email("Bill reminder", body_html))
        units_collection.update_one({"_id": u["_id"]}, {"$set": {"last_reminded_at": now}})
        sent += 1
    audit_logs_collection.insert_one({"user_id": current_user["_id"], "estate_id": estate_id, "action": "remind", "entity": "finance",
                                      "entity_id": body.unit_id or "all", "details": {"sent": sent}, "timestamp": now})
    return {"sent": sent, "skipped": skipped}


app.mount("/", socketio.ASGIApp(sio, socketio_path="socket.io"))

# Push helper (uncomment Firebase)
# def send_push(tokens: List[str], title: str, body: str):
#     if tokens:
#         message = messaging.MulticastMessage(notification=messaging.Notification(title=title, body=body), tokens=tokens)
#         messaging.send_multicast(message)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)