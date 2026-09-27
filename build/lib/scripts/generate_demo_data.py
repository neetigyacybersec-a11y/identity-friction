"""Generate the synthetic Entra ID datasets used by demo mode.

Every event this script writes is fake. The values are shaped like real
Microsoft Graph output so that demo mode and live mode travel through exactly
the same normalizer, but nothing here corresponds to a real tenant, a real
person or a real attack. Each file is stamped `"synthetic": true` and the
normalizer propagates that into `data_origin`, which the dashboard always shows.

The five scenarios are deliberately not isolated from each other. The MFA
fatigue and OAuth consent scenarios share a victim, a source IP and a
four-minute gap, so the correlation engine has something real to join into a
single incident with a readable timeline.

Run it directly:

    python scripts/generate_demo_data.py                  # rewrite data/sample/
    python scripts/generate_demo_data.py --variant 2      # shift times and users
    python scripts/generate_demo_data.py --out /tmp/try   # write somewhere else
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "data" / "sample"

# A fixed "attack day" keeps the datasets reproducible and lets the incident
# timelines read like a single shift rather than scattered noise.
BASE_DAY = datetime(2026, 9, 20, tzinfo=timezone.utc)

TENANT = "contoso-labs.onmicrosoft.com"
ATTACKER_IP = "203.0.113.77"  # TEST-NET-3, reserved for documentation
EXFIL_IP = "198.51.100.42"  # TEST-NET-2, reserved for documentation
CORP_EGRESS_IP = "192.0.2.15"  # TEST-NET-1, the office egress

LONDON = {"latitude": 51.5074, "longitude": -0.1278, "city": "London", "countryOrRegion": "GB"}
SINGAPORE = {
    "latitude": 1.3521,
    "longitude": 103.8198,
    "city": "Singapore",
    "countryOrRegion": "SG",
}
BERLIN = {
    "latitude": 52.52,
    "longitude": 13.405,
    "city": "Berlin",
    "countryOrRegion": "DE",
}
SEATTLE = {
    "latitude": 47.6062,
    "longitude": -122.3321,
    "city": "Seattle",
    "countryOrRegion": "US",
}

# Entra sign-in error codes, referenced by number so the datasets stay readable.
ERR_INVALID_CREDENTIALS = 50126
ERR_ACCOUNT_LOCKED = 50053
ERR_MFA_DENIED = 53001
ERR_MFA_DECLINED = 53002
ERR_MFA_REQUEST_DENIED = 53009
ERR_MFA_REQUIRED = 50076

SPRAY_TARGETS = [
    "j.martin",
    "a.okafor",
    "l.novak",
    "r.silva",
    "d.haddad",
    "k.tanaka",
    "p.eriksen",
]

VICTIM = {
    "userPrincipalName": f"sarah.chen@{TENANT}",
    "displayName": "Sarah Chen",
    "userType": "Member",
    "id": "9a1f0c3e-1111-4a2b-9c7d-0e5f6a7b8c9d",
}

MFA_USER = {
    "userPrincipalName": f"daniel.reyes@{TENANT}",
    "displayName": "Daniel Reyes",
    "userType": "Member",
    "id": "7b2d4e5f-2222-4b3c-8d9e-1f2a3b4c5d6e",
}

TRAVEL_USER = {
    "userPrincipalName": f"marcus.webb@{TENANT}",
    "displayName": "Marcus Webb",
    "userType": "Member",
    "id": "4c5d6e7f-3333-4c4d-9e0f-2a3b4c5d6e7f",
}

# A small, entirely fictional company. Obvious example.com-style names so no
# one can mistake a demo tenant for a real one.
BENIGN_USERS = [
    ("priya.raman", "Priya Raman"),
    ("tom.becker", "Tom Becker"),
    ("nina.petrov", "Nina Petrov"),
    ("omar.haddad", "Omar Haddad"),
    ("grace.liu", "Grace Liu"),
    ("felix.brandt", "Felix Brandt"),
]

UNAUTHORISED_APP = {
    "displayName": "Contoso Productivity Helper",
    "appId": "3f7c1d90-4e5b-4a6c-9d8e-2f3a4b5c6d7e",
    "servicePrincipalId": "6a7b8c9d-5f6e-4b7c-8d9e-3f4a5b6c7d8e",
}


def sign_in(
    *,
    at: datetime,
    user: dict,
    ip: str,
    location: dict,
    error_code: int | None = None,
    failure_reason: str | None = None,
    app: str = "Microsoft Office 365 Portal",
    device: str = "Corporate Laptop",
    auth_details: list[dict] | None = None,
    conditional_access_status: str = "success",
    event_id: str | None = None,
) -> dict:
    """Build one Graph-shaped sign-in log record.

    Shaped like `GET /v1.0/auditLogs/signIns` output: id, createdDateTime,
    user, ipAddress, location, status.errorCode, authenticationDetails.
    """
    if error_code is None:
        status = {"errorCode": 0}
    else:
        status = {"errorCode": error_code, "failureReason": failure_reason}

    if auth_details is None:
        auth_details = [
            {"authenticationMethodType": "Password", "authenticationMethod": "password", "succeeded": True}
        ]

    return {
        "id": event_id or str(uuid.uuid5(uuid.NAMESPACE_URL, f"signin-{at.isoformat()}-{user['id']}")),
        "createdDateTime": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "userPrincipalName": user["userPrincipalName"],
        "user": user,
        "ipAddress": ip,
        "location": location,
        "deviceDetail": {"displayName": device, "operatingSystem": "Windows 11", "isCompliant": True},
        "appDisplayName": app,
        "isInteractive": True,
        "isNonInteractive": False,
        "status": status,
        "conditionalAccessStatus": conditional_access_status,
        "appliedConditionalAccessPolicies": [],
        "authenticationDetails": auth_details,
        "correlationId": str(uuid.uuid5(uuid.NAMESPACE_URL, f"corr-{at.isoformat()}")),
        "riskLevelDuringSignIn": "none",
    }


def audit_entry(
    *,
    at: datetime,
    activity: str,
    category: str,
    actor: dict,
    target_display_name: str,
    target_type: str,
    added_properties: list[dict] | None = None,
    result: str = "Success",
    activity_id: str | None = None,
) -> dict:
    """Build one Graph-shaped directory audit record.

    Shaped like `GET /v1.0/auditLogs/directoryAudits` output. Granted delegated
    permissions arrive as an added property named "Permission", which is how
    the normalizer recovers them.
    """
    props = [{"name": "ConsentAction", "value": "AllPrincipals"}]
    if added_properties:
        props.extend(added_properties)

    return {
        "id": activity_id or str(uuid.uuid5(uuid.NAMESPACE_URL, f"audit-{at.isoformat()}-{activity}")),
        "activityDateTime": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "activityDisplayName": activity,
        "category": category,
        "activityResult": result,
        "result": result,
        "initiatedBy": {"user": actor, "application": None},
        "targetResources": [
            {
                "type": target_type,
                "displayName": target_display_name,
                "addedProperties": props,
            }
        ],
        "resultType": "Other",
    }


def mfa_attempt(
    *,
    at: datetime,
    user: dict,
    ip: str,
    location: dict,
    error_code: int,
    device: str = "Personal Android Phone",
) -> dict:
    """A sign-in attempt that reached the second factor and failed there.

    `authenticationDetails` carries both steps, password then push, which is
    what lets the MFA fatigue detector tell an MFA denial apart from a plain
    bad password.
    """
    return sign_in(
        at=at,
        user=user,
        ip=ip,
        location=location,
        error_code=error_code,
        failure_reason="MFA denied",
        app="Microsoft Office 365 Portal",
        device=device,
        auth_details=[
            {"authenticationMethodType": "Password", "succeeded": True},
            {
                "authenticationMethodType": "MicrosoftAuthenticatorPush",
                "succeeded": False,
                "failureReason": "UserDeclined",
            },
        ],
    )


def build_benign_logins(rng: random.Random) -> list[dict]:
    """A normal morning. Nothing here should trip a detector."""
    events: list[dict] = []
    for index, (upn_local, display_name) in enumerate(BENIGN_USERS):
        user = {
            "userPrincipalName": f"{upn_local}@{TENANT}",
            "displayName": display_name,
            "userType": "Member",
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"user-{upn_local}")),
        }
        at = BASE_DAY.replace(hour=8, minute=0) + timedelta(minutes=index * 7)
        events.append(
            sign_in(
                at=at,
                user=user,
                ip=CORP_EGRESS_IP,
                location=BERLIN,
                device="Corporate Laptop",
            )
        )

    # One user legitimately in Seattle, so the geography in this dataset is not
    # uniform. Otherwise every dataset would look identical in the dashboard.
    #
    # The gap is fourteen hours, not ninety minutes. Berlin to Seattle is about
    # 8,700 km, so a short hop implies roughly 5,800 km/h and the impossible
    # travel detector fires on a completely legitimate business trip. This is
    # the false-positive case, and the right fix is for the data to be realistic
    # rather than for the threshold to be loosened until nothing trips.
    traveler = {
        "userPrincipalName": f"priya.raman@{TENANT}",
        "displayName": "Priya Raman",
        "userType": "Member",
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "user-priya.raman")),
    }
    events.append(
        sign_in(
            at=BASE_DAY.replace(hour=22, minute=15),
            user=traveler,
            ip="198.51.100.9",
            location=SEATTLE,
            device="Corporate Laptop",
        )
    )
    rng.shuffle(events)
    return sorted(events, key=lambda event: event["createdDateTime"])


def build_password_spray(rng: random.Random) -> list[dict]:
    """Many failures, many accounts, one source IP, under ten minutes.

    A spray tries one or two common passwords against many accounts, so each
    account sees very few failures while the source IP sees a lot. That is the
    shape the detector keys on, and it is why the rule counts across accounts
    instead of per user.
    """
    events: list[dict] = []
    start = BASE_DAY.replace(hour=2, minute=0)

    for round_index in range(2):
        for user_index, local_part in enumerate(SPRAY_TARGETS):
            user = {
                "userPrincipalName": f"{local_part}@{TENANT}",
                "displayName": local_part.replace(".", " ").title(),
                "userType": "Member",
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"user-{local_part}")),
            }
            at = start + timedelta(seconds=round_index * 40 + user_index * 9)
            events.append(
                sign_in(
                    at=at,
                    user=user,
                    ip=ATTACKER_IP,
                    location={"latitude": 52.52, "longitude": 13.405, "city": "Frankfurt", "countryOrRegion": "DE"},
                    error_code=ERR_INVALID_CREDENTIALS,
                    failure_reason="BadRequest",
                    app="Office 365",
                )
            )

    # One account gives way. This is the part that matters: the spray produced
    # a foothold, and a foothold is what a later incident should notice.
    compromised = {
        "userPrincipalName": f"{SPRAY_TARGETS[2]}@{TENANT}",
        "displayName": "L Novak",
        "userType": "Member",
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"user-{SPRAY_TARGETS[2]}")),
    }
    events.append(
        sign_in(
            at=start + timedelta(minutes=9),
            user=compromised,
            ip=ATTACKER_IP,
            location={"latitude": 52.52, "longitude": 13.405, "city": "Frankfurt", "countryOrRegion": "DE"},
            app="Office 365",
            device="Unknown",
            conditional_access_status="failure",
        )
    )

    rng.shuffle(events)
    return sorted(events, key=lambda event: event["createdDateTime"])


def build_mfa_fatigue(rng: random.Random) -> list[dict]:
    """Repeated push notifications, then one the user accepts.

    Four denials in six minutes from a device the user does not normally use,
    followed by a success. The success is what separates this from a user
    fumbling their own second factor: the pattern stopped on acceptance.
    """
    start = BASE_DAY.replace(hour=10, minute=1)
    events = [
        mfa_attempt(at=start, user=MFA_USER, ip=EXFIL_IP, location=SINGAPORE, error_code=ERR_MFA_DENIED),
        mfa_attempt(
            at=start + timedelta(minutes=1),
            user=MFA_USER,
            ip=EXFIL_IP,
            location=SINGAPORE,
            error_code=ERR_MFA_DECLINED,
        ),
        mfa_attempt(
            at=start + timedelta(minutes=2),
            user=MFA_USER,
            ip=EXFIL_IP,
            location=SINGAPORE,
            error_code=ERR_MFA_REQUEST_DENIED,
        ),
        mfa_attempt(
            at=start + timedelta(minutes=4),
            user=MFA_USER,
            ip=EXFIL_IP,
            location=SINGAPORE,
            error_code=ERR_MFA_REQUIRED,
        ),
    ]

    events.append(
        sign_in(
            at=start + timedelta(minutes=5),
            user=MFA_USER,
            ip=EXFIL_IP,
            location=SINGAPORE,
            app="Microsoft Office 365 Portal",
            device="Personal Android Phone",
            auth_details=[
                {"authenticationMethodType": "Password", "succeeded": True},
                {"authenticationMethodType": "MicrosoftAuthenticatorPush", "succeeded": True},
            ],
        )
    )
    return events


def build_oauth_consent(rng: random.Random) -> list[dict]:
    """A consent grant four minutes after the MFA fatigue success.

    Sharing a user and a time window with the MFA fatigue dataset is the
    point: the correlation engine is meant to read these two files as one
    attack chain rather than two unrelated oddities.
    """
    at = BASE_DAY.replace(hour=10, minute=7)
    actor = {
        "userPrincipalName": MFA_USER["userPrincipalName"],
        "displayName": MFA_USER["displayName"],
        "userType": "Member",
        "id": MFA_USER["id"],
    }

    return [
        audit_entry(
            at=at,
            activity="Consent to application",
            category="ApplicationManagement",
            actor=actor,
            target_display_name=UNAUTHORISED_APP["displayName"],
            target_type="Service Principal",
            added_properties=[
                {"name": "Permission", "value": "Mail.Read"},
                {"name": "Permission", "value": "Mail.ReadWrite"},
                {"name": "Permission", "value": "Files.ReadWrite.All"},
                {"name": "Permission", "value": "offline_access"},
            ],
        ),
        audit_entry(
            at=at + timedelta(minutes=1),
            activity="Add service principal",
            category="ApplicationManagement",
            actor=actor,
            target_display_name=UNAUTHORISED_APP["displayName"],
            target_type="Service Principal",
        ),
    ]


def build_impossible_travel(rng: random.Random) -> list[dict]:
    """A London sign-in, then a Singapore sign-in ninety minutes later.

    About 10,900 km in 1.5 hours. No commercial flight does that, which is why
    the threshold sits at 900 km/h. The finding this produces is named
    "geographically anomalous authentication" rather than "impossible travel",
    because IP geolocation is approximate and VPNs produce the same shape.
    """
    london_user = {
        "userPrincipalName": TRAVEL_USER["userPrincipalName"],
        "displayName": TRAVEL_USER["displayName"],
        "userType": "Member",
        "id": TRAVEL_USER["id"],
    }
    return [
        sign_in(
            at=BASE_DAY.replace(hour=7, minute=15),
            user=london_user,
            ip="81.2.69.160",
            location=LONDON,
            device="Corporate Laptop",
        ),
        sign_in(
            at=BASE_DAY.replace(hour=8, minute=45),
            user=london_user,
            ip="116.86.44.201",
            location=SINGAPORE,
            device="Unknown",
            conditional_access_status="success",
        ),
    ]


def build_token_session_anomaly(rng: random.Random) -> list[dict]:
    """Session behaviour that drifts from the account's own pattern.

    Named "suspicious token or session activity" on purpose. Sign-in logs show
    *where and when* a token was used. They cannot show that it was stolen. See
    docs/adr/0002-signal-not-proof.md.
    """
    user = {
        "userPrincipalName": f"{BENIGN_USERS[2][0]}@{TENANT}",
        "displayName": BENIGN_USERS[2][1],
        "userType": "Member",
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"user-{BENIGN_USERS[2][0]}")),
    }
    start = BASE_DAY.replace(hour=14, minute=0)
    return [
        sign_in(
            at=start + timedelta(minutes=index * 3),
            user=user,
            ip="45.147.230.9",
            location={"latitude": 55.7558, "longitude": 37.6173, "city": "Moscow", "countryOrRegion": "RU"},
            app="Microsoft Graph Explorer",
            device="Unknown",
        )
        for index in range(4)
    ]


SCENARIOS = {
    "benign_login": {
        "description": "A normal working morning from the corporate egress. No detector should fire.",
        "build": build_benign_logins,
    },
    "password_spray": {
        "description": "14 failed sign-ins against 7 accounts from one IP in under 10 minutes, then one success.",
        "build": build_password_spray,
    },
    "mfa_fatigue": {
        "description": "4 MFA denials for one user in 6 minutes, then an accepted push.",
        "build": build_mfa_fatigue,
    },
    "impossible_travel": {
        "description": "London then Singapore 90 minutes apart, about 10,900 km.",
        "build": build_impossible_travel,
    },
    "oauth_consent": {
        "description": "Consent grant for an unfamiliar app with mail and file write scopes, minutes after an MFA fatigue success.",
        "build": build_oauth_consent,
    },
    "token_session_anomaly": {
        "description": "Optional: repeated graph API use from a new country. A signal, not proof of token theft.",
        "build": build_token_session_anomaly,
    },
}


def write_datasets(out_dir: Path, variant: int, seed: int) -> list[Path]:
    rng = random.Random(seed + variant)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for name, spec in SCENARIOS.items():
        events = spec["build"](rng)
        document = {
            "scenario": name,
            "synthetic": True,
            "generator": "scripts/generate_demo_data.py",
            "variant": variant,
            "description": spec["description"],
            "event_count": len(events),
            "events": events,
        }
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        written.append(path)
        print(f"  {path.relative_to(PROJECT_ROOT)}  ({len(events)} events)")

    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory")
    parser.add_argument(
        "--variant",
        type=int,
        default=0,
        help="nudge generated values so repeated runs are not byte-identical",
    )
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed, for reproducibility")
    args = parser.parse_args()

    print(f"Writing synthetic Entra datasets to {args.out} (variant {args.variant}, seed {args.seed})")
    written = write_datasets(args.out, args.variant, args.seed)
    print(f"Done. {len(written)} files. All events are synthetic and describe no real system.")


if __name__ == "__main__":
    main()
