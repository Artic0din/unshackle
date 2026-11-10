"""CDM device routes: describe, test and reprovision the server's own devices.

Unshackle keeps its Widevine (.wvd) and PlayReady (.prd) device files in the WVDs and PRDs
directories. These routes let an API client holding the ``server_cdm`` grant read what each
device's certificate says, ask the DRM vendor's own test server for a license (the clean way
to tell a burnt certificate from a healthy one), and reprovision a PlayReady device from its
group key. A device's private key material never leaves the server: describe reads only the
certificate's public fields, and test/reprovision run entirely server-side.
"""

import asyncio
import base64
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from hashlib import sha1
from pathlib import Path
from typing import Any

import requests
from aiohttp import web
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Padding
from pyplayready import InvalidCertificateChain
from pyplayready.cdm import Cdm as PlayReadyCdm
from pyplayready.crypto.ecc_key import ECCKey
from pyplayready.device import Device as PlayReadyDevice
from pyplayready.device.structs import DeviceStructs
from pyplayready.misc.exceptions import OutdatedDevice
from pyplayready.misc.revocation_list import RevocationList
from pyplayready.system.bcert import BCertCertType, Certificate
from pyplayready.system.pssh import PSSH as PlayReadyPSSH
from pywidevine.cdm import Cdm as WidevineCdm
from pywidevine.device import Device as WidevineDevice
from pywidevine.device import DeviceTypes
from pywidevine.pssh import PSSH as WidevinePSSH

from unshackle.core.api.errors import APIError, APIErrorCode
from unshackle.core.api.handlers import request_secret_key, require_admin, server_cdm_allowed
from unshackle.core.config import config

log = logging.getLogger(__name__)

KINDS = ("widevine", "playready")
NAME_MAX = 255  # bytes: the per-component filename limit on ext4, APFS and NTFS
TEST_TIMEOUT = 30  # seconds; a vendor test server answering at all is quick
TEST_SLOTS = asyncio.Semaphore(4)  # tests wait on a vendor: bound the executor threads they hold
REPROVISION_LOCK = asyncio.Lock()  # rare and quick, but two at once would fight over the same files

# Google's own Widevine test endpoint, the same one its Shaka packager tests against. A license
# from it means the certificate is good; 127/175 mean revoked. The request envelope is signed
# with the well-known test-provider key, as in Google's own examples.
WIDEVINE_TEST_URL = "https://license.widevine.com/cenc/getlicense/widevine_test"
WIDEVINE_TEST_PROVIDER = "widevine_test"
WIDEVINE_TEST_CONTENT_ID = "ZmtqM2xqYVNkZmFsa3Izag=="
WIDEVINE_TEST_AES_KEY = bytes.fromhex("1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9")
WIDEVINE_TEST_AES_IV = bytes.fromhex("d58ce954203b7c9a9a9d467f59839249")
WIDEVINE_TEST_PSSH = (
    "AAAAp3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIcSEFF0U4YtQlb9i61PWEIgBNcSEPCTfpp3yFXwptQ4ZMXZ82USEE1LDKJawVjw"
    "ucGYPFF+4rUSEJAqBRprNlaurBkm/A9dkjISECZHD0KW1F0Eqbq7RC4WmAAaDXdpZGV2aW5lX3Rlc3QiFnNoYWthX2NlYzViZmY1ZGM0"
    "MGRkYzlI49yVmwY="
)
WIDEVINE_REVOKED_CODES = (127, 175)  # DRM_DEVICE_CERTIFICATE_REVOKED, DRM_DEVICE_CERT_SERIAL_REVOKED

# Microsoft's own PlayReady test content (Tears of Steel) and test server; a license back means
# the certificate chain is accepted, a SOAP fault naming the certificate means revoked.
PLAYREADY_TEST_PSSH = (
    "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AH"
    "QAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABh"
    "AHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUg"
    "BPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQA"
    "UgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA0AFIAcABsAGIAKwBUAGIATgBFAFMAOAB0AE"
    "cAawBOAEYAVwBUAEUASABBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AEsATABqADMAUQB6AFEAUAAvAE4AQQA9ADwALwBD"
    "AEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHAAcgBvAGYAZgBpAGMAaQBhAGwAcwBpAHQAZQAuAGsAZQ"
    "B5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkAYQBzAGUAcgB2AGkAYwBlAHMALgB3AGkAbgBkAG8AdwBzAC4AbgBlAHQALwBQAGwAYQB5AFIA"
    "ZQBhAGQAeQAvADwALwBMAEEAXwBVAFIATAA+ADwAQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAF"
    "YARQBSAFMASQBPAE4APgA4AC4AMQAuADIAMwAwADQALgAzADEAPAAvAEkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBT"
    "AFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA=="
)
PLAYREADY_TEST_URL = "https://test.playready.microsoft.com/service/rightsmanager.asmx"
PLAYREADY_REVOKED_MARKERS = ("device certificate revoked", "0x8004c065")


def device_path(kind: str, name: str) -> Path:
    """The device file a kind and name resolve to, or NOT_FOUND. Names never leave the folder."""
    suffix = ".prd" if kind == "playready" else ".wvd"
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise APIError(APIErrorCode.INVALID_INPUT, f"Not a usable device name: {name!r}")
    try:
        oversized = len(os.fsencode(f"{name}{suffix}")) > NAME_MAX
    except UnicodeEncodeError:  # lone surrogates are not a filesystem name
        raise APIError(APIErrorCode.INVALID_INPUT, f"Not a usable device name: {name!r}") from None
    if oversized:
        raise APIError(APIErrorCode.INVALID_INPUT, f"Device name is too long: {name!r}")
    folder = config.directories.wvds if kind == "widevine" else config.directories.prds
    path = folder / f"{name}{suffix}"
    try:
        if path.resolve().parent != folder.resolve():
            raise APIError(APIErrorCode.INVALID_INPUT, f"Not a usable device name: {name!r}")
        if not path.is_file():
            raise APIError(APIErrorCode.NOT_FOUND, f"No {kind} device called {name!r}")
    except (OSError, ValueError):
        raise APIError(APIErrorCode.INVALID_INPUT, f"Not a usable device name: {name!r}") from None
    return path


def truncate_to_bytes(name: str, byte_budget: int) -> str:
    """As much of ``name`` as fits ``byte_budget`` filesystem bytes, cut only between characters."""
    if len(os.fsencode(name)) <= byte_budget:
        return name
    out: list[str] = []
    used = 0
    for ch in name:
        need = len(os.fsencode(ch))
        if used + need > byte_budget:
            break
        out.append(ch)
        used += need
    return "".join(out)


def device_scope_allows(request: web.Request, kind: str, name: str) -> bool:
    """Whether the calling key's ``devices``/``playready_devices`` allowlist covers ``name``.

    An unlisted key (the admin secret, or any caller in no-key mode) has every device. A listed
    key is scoped to its allowlist for the kind, and like the download flow a listed key
    without one has none of that kind's devices.
    """
    user = ((config.serve or {}).get("users") or {}).get(request_secret_key(request))
    if not isinstance(user, dict):
        return True
    allowed = user.get("devices" if kind == "widevine" else "playready_devices")
    return isinstance(allowed, (list, tuple)) and name in allowed


def describe_widevine(path: Path) -> dict[str, Any]:
    """What a .wvd's certificate says, as the API shows it; unreadable files still list."""
    found: dict[str, Any] = {"kind": "widevine", "name": path.stem}
    try:
        device = WidevineDevice.load(path)
        info = (
            {entry.name: entry.value for entry in device.client_id.client_info} if device.client_id is not None else {}
        )
        found |= {
            "system_id": device.system_id,
            "level": f"L{device.security_level}",
            "type": {DeviceTypes.CHROME: "Chrome", DeviceTypes.ANDROID: "Android"}.get(device.type, str(device.type)),
            # the FileHashes message exists even when empty; its payload is what matters (as `wvd parse` reads it)
            "vmp": bool(device.client_id.vmp_data) if device.client_id is not None else False,
        }
        for key, field in (
            ("company_name", "company"),
            ("model_name", "model"),
            ("product_name", "product"),
            ("architecture", "architecture"),
            ("widevine_cdm_version", "cdm_version"),
            ("security_patch_level", "patch_level"),
            ("build_info", "build"),
        ):
            if info.get(key):
                found[field] = info[key]
    except Exception as e:  # a corrupt or v1 file: listed, but nothing the API can say about it
        found |= {"unreadable": True, "error": str(e)}
    return found


def describe_playready(path: Path) -> dict[str, Any]:
    """What a .prd's certificate chain says, as the API shows it; unreadable files still list."""
    found: dict[str, Any] = {"kind": "playready", "name": path.stem}
    try:
        device = PlayReadyDevice.load(path)
        found |= {
            "level": f"SL{device.security_level}",
            "company": device.group_certificate.get_name(),
            "certificates": device.group_certificate.count(),
            "reprovisionable": device.group_key is not None,
        }
        try:
            found["version"] = DeviceStructs.prd.parse(path.read_bytes())["version"]
        except Exception:
            pass  # version is nice to have; the chain above already loaded
    except Exception as e:
        found |= {"unreadable": True, "error": str(e)}
    return found


def list_devices() -> dict[str, Any]:
    """Every device file in the WVDs and PRDs directories, described."""
    devices: list[dict[str, Any]] = []
    for folder, suffix, describe in (
        (config.directories.wvds, ".wvd", describe_widevine),
        (config.directories.prds, ".prd", describe_playready),
    ):
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir(), key=lambda p: p.name.lower()):
            # exact suffix: what serve itself globs, and no recovery copies (.bak)
            if path.is_file() and path.suffix == suffix:
                devices.append(describe(path))
    return {"devices": devices}


def test_widevine(path: Path) -> dict[str, Any]:
    """Ask Google's Widevine test server for a license with this device: the revocation oracle."""
    cdm = WidevineCdm.from_device(WidevineDevice.load(path))
    session_id = cdm.open()
    try:
        challenge = cdm.get_license_challenge(session_id, WidevinePSSH(WIDEVINE_TEST_PSSH))
        payload = json.dumps(
            {
                "payload": base64.b64encode(challenge).decode(),
                "provider": WIDEVINE_TEST_PROVIDER,
                "content_id": WIDEVINE_TEST_CONTENT_ID,
                "content_key_specs": [{"track_type": "SD"}, {"track_type": "HD"}, {"track_type": "AUDIO"}],
            },
            separators=(",", ":"),
        ).encode()
        request_b64 = base64.b64encode(payload).decode()
        digest = sha1(base64.b64decode(request_b64)).digest()
        signature = base64.b64encode(
            AES.new(WIDEVINE_TEST_AES_KEY, AES.MODE_CBC, WIDEVINE_TEST_AES_IV).encrypt(Padding.pad(digest, 16))
        ).decode()
        response = requests.post(
            WIDEVINE_TEST_URL,
            json={"request": request_b64, "signature": signature, "signer": WIDEVINE_TEST_PROVIDER},
            timeout=TEST_TIMEOUT,
        )
        if response.status_code != 200:
            return {"ok": False, "error": f"Test server answered HTTP {response.status_code}"}
        license_response = response.json()
        status = license_response.get("internal_status") or 0
        if status in WIDEVINE_REVOKED_CODES:
            return {"ok": False, "revoked": True, "error": f"Device certificate revoked (internal_status {status})"}
        if status != 0:
            return {"ok": False, "error": f"Test server license error (internal_status {status})"}
        license_b64 = license_response.get("license")
        if not license_b64:
            return {"ok": False, "error": "Test server returned no license"}
        cdm.parse_license(session_id, base64.b64decode(license_b64))
        return {"ok": True, "keys": len(list(cdm.get_keys(session_id)))}
    finally:
        try:
            cdm.close(session_id)
        except Exception:
            pass


def test_playready(path: Path) -> dict[str, Any]:
    """Ask Microsoft's PlayReady test server for the Tears of Steel license with this device."""
    device = PlayReadyDevice.load(path)
    server = f"{PLAYREADY_TEST_URL}?cfg=(persist:false,sl:{device.security_level},ckt:AES128BitCTR)"
    cdm = PlayReadyCdm.from_device(device)
    session_id = cdm.open()
    try:
        challenge = cdm.get_license_challenge(
            session_id, PlayReadyPSSH(PLAYREADY_TEST_PSSH).wrm_headers[0], rev_lists=RevocationList.SupportedListIds
        )
        response = requests.post(
            server,
            headers={"Content-Type": "text/xml; charset=UTF-8"},
            data=challenge,
            timeout=TEST_TIMEOUT,
        )
        body = response.text or ""
        lowered = body.lower()
        if any(marker in lowered for marker in PLAYREADY_REVOKED_MARKERS):
            return {"ok": False, "revoked": True, "error": "Device certificate revoked by the test server"}
        if response.status_code != 200:
            return {"ok": False, "error": f"Test server answered HTTP {response.status_code}"}
        try:
            cdm.parse_license(session_id, body)
        except Exception as e:
            return {"ok": False, "error": f"Test license would not parse: {e}"}
        return {"ok": True, "keys": len(list(cdm.get_keys(session_id)))}
    finally:
        try:
            cdm.close(session_id)
        except Exception:
            pass


def reprovision_playready(path: Path) -> dict[str, Any]:
    """New leaf certificate and keys from the device's group key; the old file is kept as a backup."""
    device = PlayReadyDevice.load(path)
    if device.group_key is None:
        raise APIError(
            APIErrorCode.INVALID_INPUT,
            f"{path.stem} has no group key (a version 2 device): it cannot be reprovisioned",
        )
    if device.group_certificate.get(0).get_type() != BCertCertType.DEVICE:
        raise APIError(APIErrorCode.INVALID_INPUT, f"{path.stem} is not provisioned")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # .bak, not the device suffix: a backup must stay out of every .wvd/.prd discovery glob
    def backup_name(counter: int | None = None) -> str:
        """The recovery copy's name, stem-truncated so it never tops the filename limit."""
        tail = f".backup-{stamp}{f'-{counter}' if counter is not None else ''}.bak"
        return f"{truncate_to_bytes(path.stem, NAME_MAX - len(tail))}{tail}"

    tmp: Path | None = None
    replaced = False
    backup: Path | None = None
    try:
        counter: int | None = None
        while True:
            candidate = path.with_name(backup_name(counter))
            try:
                # born 0600 and exclusively ours: no permissive copy2 window, no clobbering
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:  # a same-second reprovision never eats the first backup
                counter = 1 if counter is None else counter + 1
                continue
            backup = candidate
            break
        with os.fdopen(fd, "wb") as dst, path.open("rb") as src:
            shutil.copyfileobj(src, dst)
        shutil.copystat(path, backup)  # then the original's exact mode and timestamps
        device.group_certificate.remove(0)
        device.encryption_key = ECCKey.generate()
        device.signing_key = ECCKey.generate()
        device.group_certificate.prepend(
            Certificate.new_leaf_cert(
                cert_id=get_random_bytes(16),
                security_level=device.group_certificate.get_security_level(),
                client_id=get_random_bytes(16),
                signing_key=device.signing_key,
                encryption_key=device.encryption_key,
                group_key=device.group_key,
                parent=device.group_certificate,
            )
        )
        device.group_certificate.verify_chain(check_expiry=True, cert_type=BCertCertType.DEVICE)
        # mkstemp: a unique file born 0600, then the original's exact mode; never the umask's 0644.
        # The prefix is stem-truncated so a long device name cannot top the filename limit.
        fd, tmp_name = tempfile.mkstemp(prefix=f".{truncate_to_bytes(path.stem, 80)}.", suffix=".tmp", dir=path.parent)
        tmp = Path(tmp_name)
        with os.fdopen(fd, "wb") as f:
            f.write(device.dumps())
        os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
        replaced = True
    except (OutdatedDevice, InvalidCertificateChain) as e:
        if backup is not None:
            backup.unlink(missing_ok=True)  # the original is untouched: its backup is pointless
        raise APIError(APIErrorCode.DRM_ERROR, f"Reprovision failed, the file is untouched: {e}")
    except Exception:
        if backup is not None and not replaced:  # a replace that happened must keep its recovery copy
            backup.unlink(missing_ok=True)
        raise
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
    assert backup is not None  # the try block always sets it before reaching here
    return {"backup": backup.name, "device": describe_playready(path)}


async def list_cdm_devices(request: web.Request) -> web.Response:
    """
    Describe every CDM device on the server.
    ---
    summary: List CDM devices
    description: >-
      Every Widevine (.wvd) and PlayReady (.prd) device file in the server's WVDs/PRDs
      directories, with what its certificate says (system id, level, certificate fields) and
      whether it can be reprovisioned. A device whose file will not load is still listed, with
      unreadable set. Needs the server_cdm grant. Private key material is never returned.
    responses:
      '200':
        description: The devices, keyed by kind and name on the client side
      '403':
        description: The API key has no server_cdm grant
    """
    if not server_cdm_allowed(request):
        raise APIError(APIErrorCode.FORBIDDEN, "This API key may not read the server's CDM devices")
    return web.json_response(await asyncio.to_thread(list_devices))


async def test_cdm_device(request: web.Request) -> web.Response:
    """
    Test a CDM device against its DRM vendor's test server.
    ---
    summary: Test a CDM device
    description: >-
      Request a license from the DRM's own test server (Google's widevine_test endpoint for
      Widevine, Microsoft's Tears of Steel service for PlayReady) using the named device. A
      granted license means the certificate is healthy; revoked is set when the vendor says the
      certificate is burnt. Needs the server_cdm grant.
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [kind, name]
            properties:
              kind:
                type: string
                enum: [widevine, playready]
              name:
                type: string
                description: Device file name without its extension
    responses:
      '200':
        description: The verdict (ok, revoked and error or a key count)
      '400':
        description: Missing or unusable kind or name
      '403':
        description: >-
          The API key has no server_cdm grant, or its device allowlist does not cover
          the named device
      '404':
        description: No such device
    """
    if not server_cdm_allowed(request):
        raise APIError(APIErrorCode.FORBIDDEN, "This API key may not test the server's CDM devices")
    try:
        body = await request.json()
    except Exception:
        raise APIError(APIErrorCode.INVALID_INPUT, "Invalid JSON body")
    if not isinstance(body, dict):
        raise APIError(APIErrorCode.INVALID_INPUT, "Expected a JSON object body")
    kind, name = str(body.get("kind") or "").lower(), str(body.get("name") or "")
    if kind not in KINDS:
        raise APIError(APIErrorCode.INVALID_INPUT, "kind must be widevine or playready")
    if not device_scope_allows(request, kind, name):
        raise APIError(
            APIErrorCode.FORBIDDEN,
            f"This API key's {kind} device allowlist does not cover {name!r}",
        )
    path = device_path(kind, name)
    run = test_widevine if kind == "widevine" else test_playready
    try:
        async with TEST_SLOTS:  # each running test holds an executor thread on a vendor round-trip
            return web.json_response(await asyncio.to_thread(run, path))
    except requests.RequestException as e:
        return web.json_response({"ok": False, "error": f"Test server unreachable: {e}"})
    except APIError:
        raise
    except Exception as e:
        log.warning("CDM test failed for %s: %s", path.name, e)
        return web.json_response({"ok": False, "error": str(e)})


async def reprovision_cdm_device(request: web.Request) -> web.Response:
    """
    Reprovision a PlayReady device from its group key.
    ---
    summary: Reprovision a PlayReady device
    description: >-
      Create a new leaf certificate and fresh encryption/signing keys for the named PlayReady
      device from its group key. The previous file is kept next to it as a
      .backup-<timestamp>.bak copy, whose name is returned; the .bak suffix keeps recovery
      copies out of device discovery. Only devices with a group key (version 3) can be
      reprovisioned. Replaces a device's credentials, so it needs the admin grant, not just
      server_cdm.
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [name]
            properties:
              name:
                type: string
                description: Device file name without its .prd extension
    responses:
      '200':
        description: The backup file name and the device's new description
      '400':
        description: The device cannot be reprovisioned (no group key, not provisioned)
      '403':
        description: The API key has no server_cdm grant
      '404':
        description: No such PlayReady device
    """
    require_admin(request)  # replaces a device's credentials: a server_cdm grant alone is not enough
    try:
        body = await request.json()
    except Exception:
        raise APIError(APIErrorCode.INVALID_INPUT, "Invalid JSON body")
    if not isinstance(body, dict):
        raise APIError(APIErrorCode.INVALID_INPUT, "Expected a JSON object body")
    name = str(body.get("name") or "")
    path = device_path("playready", name)
    async with REPROVISION_LOCK:  # two at once would share backup names and a temp file
        return web.json_response(await asyncio.to_thread(reprovision_playready, path))
