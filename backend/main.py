import json
import os
import secrets
import hashlib
import hmac
import ipaddress
import psycopg
from datetime import datetime, timezone
import time
from typing import Optional, Any

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Query,
    status,
)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import requests


# ============================================================
# CONFIGURATION
# ============================================================

APP_TITLE = "Enterprise SOC Dashboard API"

SURICATA_LOG = "/var/log/suricata/eve.json"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USERS_FILE = os.path.join(BASE_DIR, "users.json")

INCIDENTS_FILE = os.path.join(BASE_DIR, "incidents.json")
IOC_FILE = os.path.join(BASE_DIR, "iocs.json")

# ============================================================
# MISP THREAT INTELLIGENCE CONFIGURATION
# ============================================================

load_dotenv(os.path.join(BASE_DIR, ".env"))

MISP_URL = os.getenv("MISP_URL", "").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
MISP_TIMEOUT = float(os.getenv("MISP_TIMEOUT", "10"))

# ============================================================
# MISP ENRICHMENT CACHE
# ============================================================
# Automatic enrichment can run whenever the alerts endpoint is
# refreshed. Cache results briefly so the dashboard does not send
# repeated MISP requests for the same IP address.
MISP_CACHE_TTL = int(os.getenv("MISP_CACHE_TTL", "60"))
MISP_CACHE = {}


# ============================================================
# POSTGRESQL DATABASE
# ============================================================

SOC_DB_CONFIG = {
    "host": os.getenv("SOC_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("SOC_DB_PORT", "5432")),
    "dbname": os.getenv("SOC_DB_NAME", "soc_dashboard"),
    "user": os.getenv("SOC_DB_USER", "soc_app"),
    "password": os.getenv("SOC_DB_PASSWORD", ""),
}



# ============================================================
# DEFAULT ADMIN
# ============================================================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SOC@12345"


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_TITLE,
    description="Enterprise SOC Dashboard API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://192.168.84.133:5500",
        "http://192.168.84.133:8080",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://192.168.84.133",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HTTP BASIC AUTH
# ============================================================

security = HTTPBasic()


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    """

    salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:
    """
    Verify a password against a stored PBKDF2 hash.
    """

    try:

        salt, password_hash = stored_hash.split("$", 1)

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100_000,
        ).hex()

        return hmac.compare_digest(
            calculated_hash,
            password_hash,
        )

    except Exception:
        return False


# ============================================================
# USER DATABASE
# ============================================================

def save_users(users: dict) -> None:
    """
    Save all users to users.json.
    """

    temp_file = USERS_FILE + ".tmp"

    with open(
        temp_file,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            users,
            file,
            indent=4,
        )

    os.replace(
        temp_file,
        USERS_FILE,
    )


def load_users() -> dict:
    """
    Load users from users.json.

    If users.json does not exist,
    automatically create the default admin.
    """

    # --------------------------------------------------------
    # Create default users file
    # --------------------------------------------------------

    if not os.path.exists(USERS_FILE):

        users = {
            ADMIN_USERNAME: {
                "username": ADMIN_USERNAME,
                "password_hash": hash_password(
                    ADMIN_PASSWORD
                ),
                "role": "admin",
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            }
        }

        save_users(users)

        return users

    # --------------------------------------------------------
    # Load existing users
    # --------------------------------------------------------

    try:

        with open(
            USERS_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            users = json.load(file)

        if not isinstance(users, dict):
            users = {}

    except Exception:

        users = {}

    # --------------------------------------------------------
    # Make sure admin always exists
    # --------------------------------------------------------

    if ADMIN_USERNAME not in users:

        users[ADMIN_USERNAME] = {
            "username": ADMIN_USERNAME,
            "password_hash": hash_password(
                ADMIN_PASSWORD
            ),
            "role": "admin",
            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        save_users(users)

    return users


# ============================================================
# INCIDENT DATABASE - POSTGRESQL
# ============================================================

def load_incidents() -> list:
    """
    Load incidents from PostgreSQL.
    """

    with psycopg.connect(**SOC_DB_CONFIG) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    alert_id,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    severity,
                    status,
                    assigned_to,
                    created_at,
                    updated_at,
                    flow_id,
                    notes,
                    created_by,
                    updated_by
                FROM incidents
                ORDER BY id
                """
            )

            rows = cursor.fetchall()

    incidents = []

    for row in rows:

        incidents.append(
            {
                "id": row[0],
                "alert_id": row[1],
                "title": row[2],
                "description": row[3],
                "source_ip": str(row[4]) if row[4] else None,
                "destination_ip": str(row[5]) if row[5] else None,
                "severity": row[6],
                "status": row[7],
                "assigned_to": row[8],
                "created_at": (
                    row[9].isoformat()
                    if row[9]
                    else None
                ),
                "updated_at": (
                    row[10].isoformat()
                    if row[10]
                    else None
                ),
                "flow_id": row[11],
                "notes": row[12] or "",
                "created_by": row[13],
                "updated_by": row[14],
            }
        )

    return incidents



# ============================================================
# IOC MANAGEMENT
# ============================================================

def load_iocs() -> list:
    """
    Load locally managed indicators of compromise from JSON.
    """
    if not os.path.exists(IOC_FILE):
        return []

    try:
        with open(
            IOC_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

    except (json.JSONDecodeError, OSError):
        pass

    return []


def save_iocs(iocs: list) -> None:
    """Save locally managed IOCs to JSON."""
    temporary_file = f"{IOC_FILE}.tmp"

    with open(
        temporary_file,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            iocs,
            file,
            indent=2,
        )

    os.replace(
        temporary_file,
        IOC_FILE,
    )


def validate_ioc_value(
    ioc_type: str,
    value: str,
) -> str:
    """
    Validate and normalize an IOC value.
    """
    value = value.strip()

    if not value:
        raise HTTPException(
            status_code=400,
            detail="IOC value is required",
        )

    ioc_type = ioc_type.upper().strip()

    if ioc_type not in {
        "IP",
        "DOMAIN",
        "URL",
        "HASH",
        "EMAIL",
    }:
        raise HTTPException(
            status_code=400,
            detail="IOC type must be IP, DOMAIN, URL, HASH, or EMAIL",
        )

    if ioc_type == "IP":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid IP address",
            )

    elif ioc_type == "EMAIL":
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise HTTPException(
                status_code=400,
                detail="Invalid email IOC",
            )

    elif ioc_type == "HASH":
        normalized_hash = value.lower()
        if len(normalized_hash) not in (32, 40, 64, 96, 128):
            raise HTTPException(
                status_code=400,
                detail="Hash IOC must be a valid MD5, SHA1, SHA256, SHA384, or SHA512 length",
            )
        if any(character not in "0123456789abcdef" for character in normalized_hash):
            raise HTTPException(
                status_code=400,
                detail="Hash IOC must contain only hexadecimal characters",
            )
        value = normalized_hash

    return value


def find_ioc_matches(
    value: Optional[str],
    ioc_type: str = "IP",
) -> list:
    """Return locally managed IOC records matching a value."""
    if not value:
        return []

    normalized_value = str(value).strip().lower()
    normalized_type = ioc_type.upper()

    return [
        ioc
        for ioc in load_iocs()
        if ioc.get("enabled", True) is True
        and str(ioc.get("type", "")).upper() == normalized_type
        and str(ioc.get("value", "")).strip().lower() == normalized_value
    ]


# ============================================================
# AUTHENTICATION
# ============================================================

def authenticate_user(
    credentials: HTTPBasicCredentials = Depends(security),
):
    """
    Authenticate an existing SOC dashboard user.
    """

    users = load_users()

    user = users.get(
        credentials.username
    )

    if user is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={
                "WWW-Authenticate": "Basic"
            },
        )

    password_valid = verify_password(
        credentials.password,
        user.get("password_hash", ""),
    )

    if not password_valid:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={
                "WWW-Authenticate": "Basic"
            },
        )

    return user


# ============================================================
# PYDANTIC MODELS
# ============================================================

class SignupRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class IOCRequest(BaseModel):
    type: str
    value: str
    threat_level: str = "MEDIUM"
    source: str = "LOCAL"
    description: str = ""
    enabled: bool = True


class IncidentRequest(BaseModel):
    alert_id: Optional[str] = None
    title: str = "Security Incident"
    description: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    severity: int = 3
    status: str = "NEW"
    assigned_to: Optional[str] = None
    flow_id: Optional[Any] = None
    notes: str = ""


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    load_users()

    load_incidents()

    print("=" * 60)
    print("Enterprise SOC Dashboard API")
    print("=" * 60)
    print("Status          : ONLINE")
    print(f"Suricata Log    : {SURICATA_LOG}")
    print("Authentication  : ENABLED")
    print(f"Admin Username  : {ADMIN_USERNAME}")
    print("Custom Signup   : ENABLED")
    print(f"Users File      : {USERS_FILE}")
    print(f"IOC File         : {IOC_FILE}")
    print("=" * 60)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "application": APP_TITLE,
        "status": "online",
        "authentication": "enabled",
        "signup": "enabled",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health(
    user=Depends(authenticate_user),
):

    return {
        "status": "healthy",
        "authenticated": True,
        "username": user["username"],
        "role": user["role"],
    }


# ============================================================
# SIGN UP
# ============================================================

@app.post("/api/signup")
def signup(
    request: SignupRequest,
):
    """
    Create a new custom SOC dashboard user.

    No authentication is required for signup.
    """

    # --------------------------------------------------------
    # Clean username
    # --------------------------------------------------------

    username = request.username.strip()

    password = request.password

    # --------------------------------------------------------
    # Validate username
    # --------------------------------------------------------

    if not username:

        raise HTTPException(
            status_code=400,
            detail="Username is required",
        )

    if len(username) < 3:

        raise HTTPException(
            status_code=400,
            detail="Username must contain at least 3 characters",
        )

    if len(username) > 50:

        raise HTTPException(
            status_code=400,
            detail="Username must not exceed 50 characters",
        )

    # --------------------------------------------------------
    # Allow only safe username characters
    # --------------------------------------------------------

    if not all(
        character.isalnum() or character in "_-.@"
        for character in username
    ):

        raise HTTPException(
            status_code=400,
            detail="Username can contain only letters, numbers, _, -, ., and @",
        )

    # --------------------------------------------------------
    # Validate password
    # --------------------------------------------------------

    if not password:

        raise HTTPException(
            status_code=400,
            detail="Password is required",
        )

    if len(password) < 6:

        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 6 characters",
        )

    # --------------------------------------------------------
    # Load existing users
    # --------------------------------------------------------

    users = load_users()

    # --------------------------------------------------------
    # Check duplicate username
    # --------------------------------------------------------

    if username in users:

        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    # --------------------------------------------------------
    # Create user
    # --------------------------------------------------------

    users[username] = {
        "username": username,
        "password_hash": hash_password(password),
        "role": "user",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    # --------------------------------------------------------
    # Save user
    # --------------------------------------------------------

    save_users(users)

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "success": True,
        "message": "Account created successfully",
        "username": username,
        "role": "user",
    }


# ============================================================
# LOGIN TEST ENDPOINT
# ============================================================

@app.post("/api/login")
def login(
    request: LoginRequest,
):
    """
    Login endpoint for frontend applications
    using JSON username/password.
    """

    users = load_users()

    username = request.username.strip()

    password = request.password

    user = users.get(username)

    if user is None:

        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
        )

    if not verify_password(
        password,
        user.get("password_hash", ""),
    ):

        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
        )

    return {
        "success": True,
        "message": "Login successful",
        "username": user["username"],
        "role": user["role"],
    }


# ============================================================
# CURRENT USER
# ============================================================

@app.get("/api/me")
def current_user(
    user=Depends(authenticate_user),
):

    return {
        "username": user["username"],
        "role": user["role"],
        "created_at": user.get(
            "created_at"
        ),
    }


# ============================================================
# USER LIST
# ============================================================

@app.get("/api/users")
def get_users(
    user=Depends(authenticate_user),
):
    """
    Return users without exposing password hashes.
    """

    users = load_users()

    safe_users = []

    for username, user_data in users.items():

        safe_users.append(
            {
                "username": user_data.get(
                    "username",
                    username,
                ),
                "role": user_data.get(
                    "role",
                    "user",
                ),
                "created_at": user_data.get(
                    "created_at"
                ),
            }
        )

    return {
        "users": safe_users,
        "count": len(safe_users),
    }


# ============================================================
# READ SURICATA LOG
# ============================================================

def read_suricata_alerts() -> list:
    """
    Read Suricata EVE JSON alerts.

    Only events of type 'alert' are returned.
    """

    alerts = []

    if not os.path.exists(SURICATA_LOG):
        return alerts

    try:

        with open(
            SURICATA_LOG,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:

                    event = json.loads(line)

                except json.JSONDecodeError:

                    continue

                if event.get("event_type") != "alert":
                    continue

                alert_data = event.get(
                    "alert",
                    {}
                )

                severity = alert_data.get(
                    "severity",
                    3,
                )

                try:
                    severity = int(severity)
                except Exception:
                    severity = 3

                # ------------------------------------------------
                # Convert Suricata severity to dashboard severity
                # ------------------------------------------------

                if severity == 1:
                    severity_name = "HIGH"

                elif severity == 2:
                    severity_name = "MEDIUM"

                else:
                    severity_name = "LOW"

                alerts.append(
                    {
                        "timestamp": event.get(
                            "timestamp"
                        ),
                        "src_ip": event.get(
                            "src_ip"
                        ),
                        "src_port": event.get(
                            "src_port"
                        ),
                        "dest_ip": event.get(
                            "dest_ip"
                        ),
                        "dest_port": event.get(
                            "dest_port"
                        ),
                        "proto": event.get(
                            "proto"
                        ),
                        "flow_id": event.get(
                            "flow_id"
                        ),
                        "event_type": event.get(
                            "event_type"
                        ),
                        "severity": severity,
                        "severity_name": severity_name,
                        "signature": alert_data.get(
                            "signature",
                            "Unknown",
                        ),
                        "signature_id": alert_data.get(
                            "signature_id"
                        ),
                        "category": alert_data.get(
                            "category",
                            "Unknown",
                        ),
                        "action": alert_data.get(
                            "action"
                        ),
                        "raw": event,
                    }
                )

    except PermissionError:

        print(
            f"Permission denied while reading {SURICATA_LOG}"
        )

    except Exception as error:

        print(
            f"Error reading Suricata log: {error}"
        )

    return alerts


# ============================================================
# AUTOMATIC MISP ALERT ENRICHMENT
# ============================================================

def get_misp_cached(ip: Optional[str]) -> dict:
    """
    Query MISP for an IP with a short in-memory cache.

    This reuses the existing threat-intelligence implementation so
    authentication, validation, MISP parsing, and error handling stay
    in one place.
    """
    if not ip:
        return {
            "ip": ip,
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_AVAILABLE",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "misp_status": "no_ip",
        }

    now = time.time()
    cached = MISP_CACHE.get(ip)

    if cached and now - cached["timestamp"] < MISP_CACHE_TTL:
        return cached["data"]

    try:
        data = threat_intelligence(ip=ip)
    except HTTPException as error:
        data = {
            "success": False,
            "ip": ip,
            "misp_status": "http_error",
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_AVAILABLE",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "message": str(error.detail),
        }
    except Exception as error:
        data = {
            "success": False,
            "ip": ip,
            "misp_status": "enrichment_error",
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_AVAILABLE",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "message": str(error),
        }

    MISP_CACHE[ip] = {
        "timestamp": now,
        "data": data,
    }

    return data


def calculate_overall_misp_threat(results: list) -> str:
    """
    Calculate the highest MISP threat level from matched IP results.

    This is deliberately independent from Suricata severity.
    """
    matched_results = [
        result for result in results
        if result.get("matched") is True
    ]

    if not matched_results:
        return "NO MATCH"

    levels = {
        str(result.get("threat_level", ""))
        .upper()
        for result in matched_results
    }

    if "HIGH" in levels:
        return "HIGH"
    if "MEDIUM" in levels:
        return "MEDIUM"
    if "LOW" in levels:
        return "LOW"

    return "MATCH FOUND"


def enrich_alert_with_misp(alert: dict) -> dict:
    """
    Automatically correlate a Suricata alert with MISP.

    The original alert fields are preserved. Enrichment is added under
    the `misp` key and summarized in top-level fields for easy frontend
    consumption.
    """
    source_ip = alert.get("src_ip")
    destination_ip = alert.get("dest_ip")

    ips = []
    for ip in (source_ip, destination_ip):
        if ip and ip not in ips:
            try:
                ipaddress.ip_address(str(ip))
                ips.append(str(ip))
            except ValueError:
                continue

    results = [get_misp_cached(ip) for ip in ips]

    source_result = next(
        (result for result in results if result.get("ip") == source_ip),
        None,
    )
    destination_result = next(
        (result for result in results if result.get("ip") == destination_ip),
        None,
    )

    total_attributes = sum(
        int(result.get("attribute_count") or 0)
        for result in results
    )
    total_events = sum(
        int(result.get("event_count") or 0)
        for result in results
    )

    overall_threat = calculate_overall_misp_threat(results)
    matched = any(
        result.get("matched") is True
        for result in results
    )

    source_iocs = find_ioc_matches(source_ip, "IP")
    destination_iocs = find_ioc_matches(destination_ip, "IP")
    local_iocs = source_iocs + destination_iocs

    enriched = dict(alert)
    enriched["misp"] = {
        "matched": matched,
        "threat_level": overall_threat,
        "attribute_count": total_attributes,
        "event_count": total_events,
        "source": source_result or {},
        "destination": destination_result or {},
        "results": results,
    }

    # Convenient summary fields for the dashboard.
    enriched["misp_matched"] = matched
    enriched["misp_threat_level"] = overall_threat
    enriched["misp_attribute_count"] = total_attributes
    enriched["misp_event_count"] = total_events

    enriched["ioc_matched"] = len(local_iocs) > 0
    enriched["ioc_match_count"] = len(local_iocs)
    enriched["ioc_matches"] = local_iocs

    return enriched


# ============================================================
# ALERTS API
# ============================================================

@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(
        100,
        ge=1,
        le=1000,
    ),
    user=Depends(authenticate_user),
):

    alerts = read_suricata_alerts()

    # Latest alerts first.
    alerts = list(
        reversed(alerts)
    )

    # ------------------------------------------------------------
    # Automatic Suricata -> MISP correlation
    # ------------------------------------------------------------
    # Enrich only the alerts that will actually be returned. This
    # keeps the endpoint responsive while still giving the frontend
    # MISP intelligence automatically.
    limited_alerts = [
        enrich_alert_with_misp(alert)
        for alert in alerts[:limit]
    ]

    return {
        "alerts": limited_alerts,
        "count": len(limited_alerts),
        "total": len(alerts),
        "authenticated_user": user["username"],
    }


# ============================================================
# STATISTICS API
# ============================================================

@app.get("/api/statistics")
def get_statistics(
    user=Depends(authenticate_user),
):

    alerts = read_suricata_alerts()

    high = 0
    medium = 0
    low = 0

    for alert in alerts:

        severity = alert.get(
            "severity",
            3,
        )

        if severity == 1:
            high += 1

        elif severity == 2:
            medium += 1

        else:
            low += 1

    total = high + medium + low

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "statistics": {
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
        },
        "authenticated_user": user["username"],
    }


# ============================================================
# INCIDENTS - GET
# ============================================================

@app.get("/api/incidents")
def get_incidents(
    user=Depends(authenticate_user),
):
    """
    Return all incidents from PostgreSQL.
    """

    incidents = load_incidents()

    return {
        "incidents": incidents,
        "count": len(incidents),
        "authenticated_user": user["username"],
    }


# ============================================================
# INCIDENTS - CREATE
# ============================================================

@app.post("/api/incidents")
def create_incident(
    request: IncidentRequest,
    user=Depends(authenticate_user),
):
    """
    Create an incident directly in PostgreSQL.
    """

    with psycopg.connect(**SOC_DB_CONFIG) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO incidents (
                    alert_id,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    severity,
                    status,
                    assigned_to,
                    flow_id,
                    notes,
                    created_by,
                    updated_by
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                RETURNING
                    id,
                    alert_id,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    severity,
                    status,
                    assigned_to,
                    created_at,
                    updated_at,
                    flow_id,
                    notes,
                    created_by,
                    updated_by
                """,
                (
                    request.alert_id,
                    request.title,
                    request.description,
                    request.source_ip,
                    request.destination_ip,
                    request.severity,
                    request.status,
                    request.assigned_to,
                    request.flow_id,
                    request.notes,
                    user["username"],
                    user["username"],
                ),
            )

            row = cursor.fetchone()

    incident = {
        "id": row[0],
        "alert_id": row[1],
        "title": row[2],
        "description": row[3],
        "source_ip": str(row[4]) if row[4] else None,
        "destination_ip": str(row[5]) if row[5] else None,
        "severity": row[6],
        "status": row[7],
        "assigned_to": row[8],
        "created_at": row[9].isoformat() if row[9] else None,
        "updated_at": row[10].isoformat() if row[10] else None,
        "flow_id": row[11],
        "notes": row[12] or "",
        "created_by": row[13],
        "updated_by": row[14],
    }

    return {
        "success": True,
        "message": "Incident created successfully",
        "incident": incident,
    }


# ============================================================
# INCIDENT - UPDATE
# ============================================================

@app.put("/api/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    request: IncidentRequest,
    user=Depends(authenticate_user),
):
    """
    Update an incident directly in PostgreSQL.
    """

    with psycopg.connect(**SOC_DB_CONFIG) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                UPDATE incidents
                SET
                    alert_id = %s,
                    title = %s,
                    description = %s,
                    source_ip = %s,
                    destination_ip = %s,
                    severity = %s,
                    status = %s,
                    assigned_to = %s,
                    flow_id = %s,
                    notes = %s,
                    updated_by = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING
                    id,
                    alert_id,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    severity,
                    status,
                    assigned_to,
                    created_at,
                    updated_at,
                    flow_id,
                    notes,
                    created_by,
                    updated_by
                """,
                (
                    request.alert_id,
                    request.title,
                    request.description,
                    request.source_ip,
                    request.destination_ip,
                    request.severity,
                    request.status,
                    request.assigned_to,
                    request.flow_id,
                    request.notes,
                    user["username"],
                    incident_id,
                ),
            )

            row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    incident = {
        "id": row[0],
        "alert_id": row[1],
        "title": row[2],
        "description": row[3],
        "source_ip": str(row[4]) if row[4] else None,
        "destination_ip": str(row[5]) if row[5] else None,
        "severity": row[6],
        "status": row[7],
        "assigned_to": row[8],
        "created_at": row[9].isoformat() if row[9] else None,
        "updated_at": row[10].isoformat() if row[10] else None,
        "flow_id": row[11],
        "notes": row[12] or "",
        "created_by": row[13],
        "updated_by": row[14],
    }

    return {
        "success": True,
        "message": "Incident updated successfully",
        "incident": incident,
    }


# ============================================================
# INCIDENT - DELETE
# ============================================================

@app.delete("/api/incidents/{incident_id}")
def delete_incident(
    incident_id: int,
    user=Depends(authenticate_user),
):
    """
    Delete an incident directly from PostgreSQL.
    """

    with psycopg.connect(**SOC_DB_CONFIG) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                DELETE FROM incidents
                WHERE id = %s
                RETURNING id
                """,
                (incident_id,),
            )

            deleted = cursor.fetchone()

    if deleted is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "success": True,
        "message": "Incident deleted successfully",
        "incident_id": incident_id,
    }


# ============================================================
# INCIDENTS - CREATE
# ============================================================



# ============================================================
# INCIDENT - UPDATE
# ============================================================



# ============================================================
# INCIDENT - DELETE
# ============================================================



# ============================================================
# DELETE USER
# ============================================================

@app.delete("/api/users/{username}")
def delete_user(
    username: str,
    user=Depends(authenticate_user),
):
    """
    Only admin can delete users.
    """

    if user.get("role") != "admin":

        raise HTTPException(
            status_code=403,
            detail="Only administrators can delete users",
        )

    username = username.strip()

    if username == ADMIN_USERNAME:

        raise HTTPException(
            status_code=400,
            detail="The default admin account cannot be deleted",
        )

    users = load_users()

    if username not in users:

        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    del users[username]

    save_users(
        users
    )

    return {
        "success": True,
        "message": f"User '{username}' deleted successfully",
    }


# ============================================================
# IOC MANAGEMENT API
# ============================================================

@app.get("/api/iocs")
def get_iocs(
    user=Depends(authenticate_user),
):
    """Return all locally managed IOCs."""
    iocs = load_iocs()
    return {
        "iocs": iocs,
        "count": len(iocs),
        "enabled_count": sum(
            1 for ioc in iocs
            if ioc.get("enabled", True) is True
        ),
        "authenticated_user": user["username"],
    }


@app.post("/api/iocs")
def create_ioc(
    request: IOCRequest,
    user=Depends(authenticate_user),
):
    """Create a locally managed IOC."""
    ioc_type = request.type.upper().strip()
    value = validate_ioc_value(ioc_type, request.value)
    threat_level = request.threat_level.upper().strip()

    if threat_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(
            status_code=400,
            detail="Threat level must be LOW, MEDIUM, HIGH, or CRITICAL",
        )

    iocs = load_iocs()

    duplicate = next(
        (
            ioc for ioc in iocs
            if str(ioc.get("type", "")).upper() == ioc_type
            and str(ioc.get("value", "")).strip().lower() == value.lower()
        ),
        None,
    )

    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail="IOC already exists",
        )

    next_id = max(
        [int(ioc.get("id", 0)) for ioc in iocs if str(ioc.get("id", "")).isdigit()] or [0]
    ) + 1

    now = datetime.now(timezone.utc).isoformat()

    ioc = {
        "id": next_id,
        "type": ioc_type,
        "value": value,
        "threat_level": threat_level,
        "source": request.source.strip() or "LOCAL",
        "description": request.description.strip(),
        "enabled": bool(request.enabled),
        "created_at": now,
        "updated_at": now,
        "created_by": user["username"],
        "updated_by": user["username"],
    }

    iocs.append(ioc)
    save_iocs(iocs)

    return {
        "success": True,
        "message": "IOC created successfully",
        "ioc": ioc,
    }


@app.put("/api/iocs/{ioc_id}")
def update_ioc(
    ioc_id: int,
    request: IOCRequest,
    user=Depends(authenticate_user),
):
    """Update a locally managed IOC."""
    iocs = load_iocs()

    target = next(
        (ioc for ioc in iocs if int(ioc.get("id", -1)) == ioc_id),
        None,
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    ioc_type = request.type.upper().strip()
    value = validate_ioc_value(ioc_type, request.value)
    threat_level = request.threat_level.upper().strip()

    if threat_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(
            status_code=400,
            detail="Threat level must be LOW, MEDIUM, HIGH, or CRITICAL",
        )

    duplicate = next(
        (
            ioc for ioc in iocs
            if int(ioc.get("id", -1)) != ioc_id
            and str(ioc.get("type", "")).upper() == ioc_type
            and str(ioc.get("value", "")).strip().lower() == value.lower()
        ),
        None,
    )

    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail="Another IOC with the same type and value already exists",
        )

    now = datetime.now(timezone.utc).isoformat()

    target.update({
        "type": ioc_type,
        "value": value,
        "threat_level": threat_level,
        "source": request.source.strip() or "LOCAL",
        "description": request.description.strip(),
        "enabled": bool(request.enabled),
        "updated_at": now,
        "updated_by": user["username"],
    })

    save_iocs(iocs)

    return {
        "success": True,
        "message": "IOC updated successfully",
        "ioc": target,
    }


@app.delete("/api/iocs/{ioc_id}")
def delete_ioc(
    ioc_id: int,
    user=Depends(authenticate_user),
):
    """Delete a locally managed IOC."""
    iocs = load_iocs()

    remaining = [
        ioc for ioc in iocs
        if int(ioc.get("id", -1)) != ioc_id
    ]

    if len(remaining) == len(iocs):
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    save_iocs(remaining)

    return {
        "success": True,
        "message": "IOC deleted successfully",
        "ioc_id": ioc_id,
    }


# ============================================================
# MISP THREAT INTELLIGENCE
# ============================================================

@app.get("/api/threat-intel")
def threat_intelligence(
    ip: str = Query(..., description="IPv4 or IPv6 address to investigate")
):
    """
    Search an IP address in MISP using the MISP REST API.
    The MISP API key remains on the backend and is never exposed
    to the frontend.
    """

    ip = ip.strip()

    if not ip:
        raise HTTPException(
            status_code=400,
            detail="IP address is required",
        )

    # Validate IPv4/IPv6 input before sending it to MISP.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IPv4 or IPv6 address",
        )

    if not MISP_URL or not MISP_API_KEY:
        return {
            "success": False,
            "ip": ip,
            "misp_status": "not_configured",
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_CONFIGURED",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "message": "MISP configuration is missing",
        }

    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {
        "returnFormat": "json",
        "value": ip,
    }

    try:
        response = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=headers,
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=MISP_TIMEOUT,
        )

        if response.status_code in (401, 403):
            raise HTTPException(
                status_code=502,
                detail="MISP authentication failed. Check the API key.",
            )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            return {
                "success": False,
                "ip": ip,
                "misp_status": "invalid_response",
                "matched": False,
                "threat_level": "UNKNOWN",
                "reputation": "UNKNOWN",
                "attribute_count": 0,
                "event_count": 0,
                "events": [],
                "attributes": [],
                "message": "MISP returned an unexpected response format",
            }
        response_data = data.get("response", {})

        attributes = response_data.get("Attribute", [])

        # MISP can return a list or a dictionary depending on the
        # endpoint/result format.
        if isinstance(attributes, dict):
            attributes = [attributes]

        events = []
        seen_events = set()

        for attribute in attributes:
            event = attribute.get("Event", {})

            if not isinstance(event, dict):
                event = {}

            event_id = str(
                event.get("id")
                or attribute.get("event_id")
                or ""
            )

            if event_id and event_id not in seen_events:
                seen_events.add(event_id)

                events.append({
                    "id": event_id,
                    "info": event.get("info", ""),
                    "date": event.get("date", ""),
                    "orgc_name": event.get("Orgc", {}).get("name", "")
                    if isinstance(event.get("Orgc"), dict)
                    else "",
                })

        return {
            "success": True,
            "ip": ip,
            "misp_status": "connected",
            "matched": len(attributes) > 0,
            "threat_level": "UNKNOWN",
            "reputation": "MATCH_FOUND" if attributes else "NO_MATCH",
            "attribute_count": len(attributes),
            "event_count": len(events),
            "events": events,
            "attributes": [
                {
                    "id": attribute.get("id"),
                    "type": attribute.get("type"),
                    "category": attribute.get("category"),
                    "value": attribute.get("value"),
                    "comment": attribute.get("comment", ""),
                    "to_ids": attribute.get("to_ids"),
                }
                for attribute in attributes
            ],
        }

    except HTTPException:
        raise

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "ip": ip,
            "misp_status": "timeout",
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_AVAILABLE",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "message": "MISP request timed out",
        }

    except requests.exceptions.RequestException as error:
        return {
            "success": False,
            "ip": ip,
            "misp_status": "connection_error",
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_AVAILABLE",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "message": str(error),
        }

    except ValueError:
        return {
            "success": False,
            "ip": ip,
            "misp_status": "invalid_response",
            "matched": False,
            "threat_level": "UNKNOWN",
            "reputation": "NOT_AVAILABLE",
            "attribute_count": 0,
            "event_count": 0,
            "events": [],
            "attributes": [],
            "message": "MISP returned invalid JSON",
        }


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
