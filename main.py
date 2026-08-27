# NEXHOOD BACKEND BUILD MARKER: v24-2026-08-15-security-fixes-idor-privesc
# If /health below doesn't return this exact build string, the running
# process is NOT this file — kill whatever's on port 8000 and restart.
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, UploadFile, File, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator
from pymongo import MongoClient
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import re
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
            result[key] = value.isoformat()
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
app = FastAPI(title="NexHood Backend", description="Backend for estate security management")

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
    login_logs_collection = db["login_logs"]
    client.server_info()
    logger.info("Connected to MongoDB")
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    raise

# Geo index for locations
incidents_collection.create_index([("location", "2dsphere")])
alerts_collection.create_index([("location", "2dsphere")])

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
    title: str = Field(..., min_length=3)
    description: str = Field(..., min_length=10)
    location: Optional[Dict] = None
    images: Optional[List[str]] = None


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
    content: str = Field(..., min_length=1)
    type: str = Field(..., pattern="^(event|appreciation|general)$")
    # Data URIs (e.g. "data:image/jpeg;base64,...") from /api/upload/image —
    # kept small in practice by the frontend's client-side size cap, since
    # these get embedded directly in the Mongo document, not object storage.
    images: Optional[List[str]] = None


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
    return {k: str(v) if isinstance(v, ObjectId) else v for k, v in data.items()}


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
BUILD_VERSION = "v24-2026-08-15-security-fixes-idor-privesc"


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
    """Public self-registration. Only residents can self-register; the first
    resident to register under a given estate name becomes that estate's
    admin. Guards/admins/police are created via the invite endpoints below,
    not through this route."""
    if user.role != "resident":
        raise HTTPException(status_code=400, detail="Only residents can register publicly.")

    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="User already exists")

    if not user.estate_id or not str(user.estate_id).strip():
        raise HTTPException(status_code=400, detail="Estate name is required")

    estate_name = str(user.estate_id).strip()

    # Auto-create the estate if it doesn't exist yet.
    estate = estates_collection.find_one({"name": estate_name})
    if not estate:
        estate_doc = {
            "name": estate_name,
            "address": f"{estate_name}, Nigeria",
            "created_at": datetime.utcnow()
        }
        estate_result = estates_collection.insert_one(estate_doc)
        estate_id = estate_result.inserted_id
    else:
        estate_id = estate["_id"]

    hashed_password = get_password_hash(user.password)

    user_dict = user.dict(exclude_unset=True)
    user_dict.update({
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
            f"<p>Hi {user.name},</p>"
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

    user = users_collection.find_one({"email": request.email})
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
    user = users_collection.find_one({"email": request.email})
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
    return {"message": "Password reset successfully. You can now log in with your new password."}


@app.post("/api/contact")
async def submit_contact(msg: ContactMessageCreate):
    """Landing page 'Contact us' form. Stored in Mongo first so a message
    is never lost even if the email send fails, then emails CONTACT_EMAIL
    with the details and sends the person a short confirmation so they know
    it actually went somewhere instead of vanishing into a form."""
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
            f"<p><strong>From:</strong> {msg.name} ({msg.email})</p>"
            f"<p><strong>Message:</strong></p>"
            f"<p style='white-space:pre-wrap;'>{msg.message}</p>"
        )
    )
    send_email(
        msg.email,
        "We got your message — Nexhood",
        branded_email(
            "Thanks for reaching out",
            f"<p>Hi {msg.name},</p>"
            f"<p>Thanks for reaching out to Nexhood — we've received your message and will get back to you soon.</p>"
            f"<p style='color:#9ca3af;font-size:12px;border-left:2px solid #e5e7eb;padding-left:10px;'>{msg.message}</p>"
        )
    )

    return {"message": "Thanks — we've received your message and will get back to you soon.", "id": str(result.inserted_id)}


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
                f"<p>Hi {pass_dict['visitor_name']},</p>"
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

    pass_data_db = passes_collection.find_one({"code": code})
    if not pass_data_db or str(pass_data_db["estate_id"]) != str(current_user["estate_id"]):
        logger.error(f"Validation failed for code {code}: pass_data_db={pass_data_db}, user_estate_id={current_user['estate_id']}")
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
async def create_incident(incident: IncidentCreate, current_user: Dict = Depends(get_current_user)):
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
        admins = list(users_collection.find({"estate_id": ObjectId(current_user["estate_id"]), "role": {"$in": ["admin", "guard"]}}, {"email": 1}))
        for admin in admins:
            send_email(
                admin.get("email"),
                f"NexHood ALERT: {incident.severity.upper()} incident reported",
                branded_email(
                    f"{incident.severity.capitalize()} incident reported",
                    f"<p><strong>{incident.title}</strong></p>"
                    f"<p>{incident.description}</p>"
                    f"<p>Reported by {current_user['name']}. Check the app for full details.</p>"
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
async def update_incident(incident_id: str, status: Optional[str] = None, assigned_to: Optional[str] = None, response: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    if current_user["role"] not in ["guard", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    incident = incidents_collection.find_one({"_id": ObjectId(incident_id)})
    if not incident or str(incident["estate_id"]) != str(current_user["estate_id"]):
        logger.error(f"Update failed for incident {incident_id}: incident={incident}, user_estate_id={current_user['estate_id']}")
        raise HTTPException(status_code=404, detail="Incident not found")
    update_set = {}
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
        "action": "update",
        "entity": "incident",
        "entity_id": incident_id,
        "details": update_ops,
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
    users_collection.update_one({"_id": ObjectId(current_user["_id"])}, {"$push": {"badges": BadgeAward(badge="Hero Resolver").dict()}})
    return {"message": "Incident resolved"}


@app.post("/api/alerts")
async def create_alert(alert: AlertCreate, current_user: Dict = Depends(get_current_user)):
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

        if alert.priority in ["high", "critical"]:
            estate = estates_collection.find_one({"_id": ObjectId(current_user["estate_id"])})
            emergency_contacts = (estate or {}).get("settings", {}).get("emergencyContacts", [])
            for contact in emergency_contacts:
                if contact.get("email"):
                    send_email(
                        contact["email"],
                        f"NexHood EMERGENCY ALERT ({alert.priority.upper()}): {alert.type}",
                        branded_email(
                            f"{alert.priority.capitalize()} priority alert",
                            f"<p>A {alert.priority} priority alert was raised at your estate.</p>"
                            f"<p><strong>{alert.type.replace('_', ' ').title()}</strong></p>"
                            f"<p>{alert.message or 'No details provided'}</p>"
                            f"<p>Raised by {current_user.get('name', 'a resident')}.</p>"
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
        f"<p><strong>Message:</strong> {alert.get('message', 'No details provided')}</p>"
        f"<p><strong>Reported by:</strong> {current_user.get('name', 'A resident')} ({current_user.get('phone', 'no phone on file')})</p>"
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
    if users_collection.find_one({"email": invite.email}):
        raise HTTPException(status_code=400, detail="User already exists")

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
        "email": invite.email,
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
        invite.email,
        f"You've been invited to {estate_name}",
        branded_email(
            "You've been invited",
            f"<p>Hi {invite.name},</p>"
            f"<p>You've been added to <strong>{estate_name}</strong> on NexHood as a <strong>{invite.role}</strong>.</p>"
            f"<p>Login email: {invite.email}<br>Temporary password: <strong>{temp_password}</strong></p>"
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
        "email": invite.email,
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
        try:
            if users_collection.find_one({"email": email}):
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
                    f"<p>Hi {name},</p>"
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


@app.get("/api/analytics/dashboard")
async def get_dashboard(start_date: Optional[str] = None, end_date: Optional[str] = None, current_user: Dict = Depends(get_current_user)):
    role = current_user["role"].lower()
    # A true platform-wide super_admin (see /api/platform/stats) has no
    # estate_id at all — this used to convert it to ObjectId() unconditionally
    # up here and crash with a 500 before ever reaching the super_admin
    # branch below, which is the one case that doesn't need it.
    estate_id = ObjectId(current_user["estate_id"]) if current_user.get("estate_id") else None
    if role not in ["admin", "super_admin"] and estate_id is None:
        raise HTTPException(status_code=400, detail="Account has no estate")

    if role in ["admin", "super_admin"]:
        date_filter = {}
        try:
            if start_date and end_date:
                date_filter = {"created_at": {"$gte": datetime.fromisoformat(start_date), "$lte": datetime.fromisoformat(end_date)}}
            elif start_date:
                date_filter = {"created_at": {"$gte": datetime.fromisoformat(start_date)}}
            elif end_date:
                date_filter = {"created_at": {"$lte": datetime.fromisoformat(end_date)}}
            else:
                date_filter = {"created_at": {"$gte": datetime.utcnow() - timedelta(days=30)}}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")

        estate_filter = {} if role == "super_admin" else {"estate_id": estate_id}

        total_visitors = passes_collection.count_documents({**estate_filter, **date_filter})
        active_incidents = incidents_collection.count_documents({**estate_filter, "status": {"$nin": ["resolved", "closed"]}})
        total_alerts = alerts_collection.count_documents({**estate_filter, **date_filter})
        active_alerts = alerts_collection.count_documents({**estate_filter, "status": {"$in": ["active", "acknowledged"]}})
        recent_activity = list(audit_logs_collection.find({**estate_filter, **date_filter}).sort("timestamp", -1).limit(20))

        incident_trends = list(incidents_collection.aggregate([
            {"$match": {**estate_filter, **date_filter}},
            {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}}, "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))
        visitor_trends = list(passes_collection.aggregate([
            {"$match": {**estate_filter, **date_filter}},
            {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}}, "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))
        incident_types = list(incidents_collection.aggregate([
            {"$match": {**estate_filter, **date_filter}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}}
        ]))
        # Which open incidents actually need urgent attention right now —
        # a type breakdown alone doesn't tell an admin what's on fire today.
        incident_severity_open = list(incidents_collection.aggregate([
            {"$match": {**estate_filter, "status": {"$nin": ["resolved", "closed"]}}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]))
        # Roles are the whole picture here, not just a single "users" count —
        # an admin needs to see residents vs guards vs police at a glance,
        # and this also makes the invite-cap (3 admins) visible without
        # digging into the Users page.
        users_by_role = list(users_collection.aggregate([
            {"$match": {**estate_filter, "is_active": True}},
            {"$group": {"_id": "$role", "count": {"$sum": 1}}}
        ]))
        pass_status = list(passes_collection.aggregate([
            {"$match": {**estate_filter, **date_filter}},
            {"$group": {"_id": "$status", "count": {"$sum": 1}}}
        ]))
        alert_status = list(alerts_collection.aggregate([
            {"$match": {**estate_filter, **date_filter}},
            {"$group": {"_id": "$status", "count": {"$sum": 1}}}
        ]))
        alert_types = list(alerts_collection.aggregate([
            {"$match": {**estate_filter, **date_filter}},
            {"$group": {"_id": "$type", "count": {"$sum": 1}}}
        ]))
        # Welfare/community are part of "everything happening in the estate"
        # too, not just security events — surfaced here so admins don't have
        # to bounce between pages to see if anyone's actually engaging.
        posts_30d = posts_collection.count_documents({**estate_filter, **date_filter})
        # Only verified donations count here — an unconfirmed pledge
        # shouldn't show up as money the estate has actually raised.
        welfare_raised_agg = list(donations_collection.aggregate([
            {"$match": {**estate_filter, "status": "verified"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        welfare_raised_total = welfare_raised_agg[0]["total"] if welfare_raised_agg else 0
        active_campaigns = campaigns_collection.count_documents({**estate_filter, "status": {"$ne": "closed"}})

        analytics_data = {
            "summary": {
                "total_visitors": total_visitors,
                "active_incidents": active_incidents,
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "total_users": users_collection.count_documents({**estate_filter, "is_active": True})
            },
            "trends": {"incidents": incident_trends, "visitors": visitor_trends},
            "distributions": {
                "incident_types": incident_types,
                "incident_severity_open": incident_severity_open,
                "users_by_role": users_by_role,
                "pass_status": pass_status,
                "alert_status": alert_status,
                "alert_types": alert_types
            },
            "engagement": {
                "posts_last_30d": posts_30d,
                "welfare_raised_total": welfare_raised_total,
                "active_campaigns": active_campaigns
            },
            "recent_activity": recent_activity
        }
        return serialize_doc(analytics_data)

    else:
        data = {
            "summary": {
                "active_incidents": incidents_collection.count_documents({"estate_id": estate_id, "reporter_id": current_user["_id"], "status": {"$ne": "resolved"}}),
                "total_visitors": passes_collection.count_documents({"estate_id": estate_id, "host_id": current_user["_id"]}),
                "total_alerts": alerts_collection.count_documents({"estate_id": estate_id, "sender_id": current_user["_id"], "status": "active"}),
                "total_users": 0
            },
            "recentIncidents": list(incidents_collection.find({"estate_id": estate_id, "reporter_id": current_user["_id"]}).sort("created_at", -1).limit(5))
        }
        return serialize_doc(data)


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
                pass_data = passes_collection.find_one({"code": action.data["code"]})
                if pass_data and str(pass_data["estate_id"]) == str(current_user["estate_id"]):
                    passes_collection.update_one(
                        {"_id": pass_data["_id"]},
                        {"$set": {"status": "used", "used_at": action.timestamp, "used_by": ObjectId(current_user["_id"])}}
                    )
                    result.update({"success": True, "data": to_json_serializable({**pass_data, "id": str(pass_data["_id"])})})
                else:
                    result.update({"success": False, "error": "Invalid pass or unauthorized estate"})
            elif action.type == "create_incident":
                incident_dict = action.data
                incident_dict.update({
                    "reporter_id": ObjectId(current_user["_id"]),
                    "estate_id": ObjectId(current_user["estate_id"]),
                    "status": incident_dict.get("status", "reported"),
                    "created_at": action.timestamp
                })
                result_id = incidents_collection.insert_one(incident_dict).inserted_id
                result.update({"success": True, "data": to_json_serializable({**incident_dict, "id": str(result_id)})})
            elif action.type == "create_alert":
                alert_dict = action.data
                alert_dict.update({
                    "sender_id": ObjectId(current_user["_id"]),
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

    if current_user["role"].lower() not in ["admin", "super_admin"]:
        query_filter["host_id"] = current_user["_id"]

    if status:
        query_filter["status"] = status
    if start_date and end_date:
        try:
            query_filter["created_at"] = {"$gte": datetime.fromisoformat(start_date), "$lte": datetime.fromisoformat(end_date)}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")

    passes = passes_collection.find(query_filter).sort("created_at", -1).limit(100)
    return [serialize_doc(p) for p in passes]


@app.post("/api/community/posts")
async def create_post(post: PostCreate, current_user: Dict = Depends(get_current_user)):
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
    # Mock Paystack link (replace with a real Paystack initialize call before launch)
    paystack_link = f"https://paystack.com/pay/nexhood-{donation.for_role}-{donation.amount}"
    return {"paystack_link": paystack_link, "donation_id": str(result.inserted_id), "status": "pending"}


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

    if "email" in changes and changes["email"].lower() != current_user["email"].lower():
        if users_collection.find_one({"email": changes["email"], "_id": {"$ne": ObjectId(current_user["_id"])}}):
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

    return {"message": "Password changed successfully"}


app.mount("/", socketio.ASGIApp(sio, socketio_path="socket.io"))

# Push helper (uncomment Firebase)
# def send_push(tokens: List[str], title: str, body: str):
#     if tokens:
#         message = messaging.MulticastMessage(notification=messaging.Notification(title=title, body=body), tokens=tokens)
#         messaging.send_multicast(message)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)