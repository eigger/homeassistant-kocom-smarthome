import hashlib
import base64
import aiohttp
import json

from .const import LOGGER

def generate_digest_header(username: str, password: str, uri: str, nonce: str) -> str:
    """Creates digest authentication header string."""
    username_hash = hashlib.md5(f"{username}:kbranch:{password}".encode()).hexdigest()
    uri_hash = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{username_hash}:{nonce}:{uri_hash}".encode()).hexdigest()
    return f'Digest username="{username}", realm="kbranch", nonce="{nonce}", uri="{uri}", response="{response}"'

def generate_constant_fcm_token(phone_number: str) -> str:
    """Generates FCM tokens that do not change based on the given mobile phone number."""
    hash_object = hashlib.sha256(phone_number.encode())
    constant_token = base64.urlsafe_b64encode(hash_object.digest()).decode("utf-8")
    return constant_token

async def firebase_device_setup(session: aiohttp.ClientSession) -> str:
    """Sets up the Firebase device asynchronously."""

    # Define headers for Firebase installations
    headers = {
        "x-firebase-client": "apple-platform/ios",
        "x-ios-bundle-identifier": "com.kocom.SmartHome2",
        "user-agent": "SmartHome/46 CFNetwork/1568.200.51 Darwin/24.1.0",
        "x-goog-api-key": "AIzaSyBQwyatsILIBXE6Xg6-IPNANVPqoUTCRYg"
    }

    # Firebase installations data
    installation_data = {
        "appId": "1:444087228688:android:1aecd4752f9aec0fd92d95",
        "authVersion": "FIS_v2",
        "sdkVersion": "i:10.12.0"
    }

    # Asynchronous Firebase installations request
    url_installations = "https://firebaseinstallations.googleapis.com/v1/projects/q43sw-ff29c/installations/"
    async with session.post(url_installations, headers=headers, json=installation_data) as response:
        response.raise_for_status()
        installation_response = await response.json()

    fid = installation_response.get("fid")
    auth_token = installation_response.get("authToken", {}).get("token")
    LOGGER.debug(f"Firebase Installation ID (FID): {fid}")
    LOGGER.debug(f"Authentication Token: {auth_token}")

    # Device check-in data
    checkin_data = {
        "locale": "ko_KR",
        "digest": "",
        "checkin": {
            "iosbuild": {
                "model": "iPhone16,2",
                "os_version": "IOS_18.1"
            },
            "last_checkin_msec": 0,
            "user_number": 0,
            "type": 2
        },
        "time_zone": "Asia/Seoul",
        "user_serial_number": 0,
        "id": 0,
        "version": 2,
        "security_token": 0,
        "fragment": 0
    }

    # Asynchronous device check-in request
    url_checkin = "https://device-provisioning.googleapis.com/checkin"
    async with session.post(url_checkin, headers={"user-agent": "SmartHome/46 CFNetwork/1568.200.51 Darwin/24.1.0"}, json=checkin_data) as response:
        response.raise_for_status()
        checkin_response = await response.json()

    security_token = checkin_response.get("security_token")
    android_id = checkin_response.get("android_id")
    version_info = checkin_response.get("version_info")
    LOGGER.debug(f"Security Token: {security_token}")
    LOGGER.debug(f"Android ID: {android_id}")
    LOGGER.debug(f"Version Info: {version_info}")

    # Device registration data
    register_headers = {
        "content-type": "application/x-www-form-urlencoded",
        "x-firebase-client": "apple-platform/ios",
        "authorization": f"AidLogin {android_id}:{security_token}",
        "x-firebase-client-log-type": "2",
        "app": "com.kocom.SmartHome2",
        "user-agent": "SmartHome/46 CFNetwork/1568.200.51 Darwin/24.1.0",
        "info": version_info,
        "x-goog-firebase-installations-auth": auth_token
    }

    register_data = {
        "X-osv": "18.1",
        "device": android_id,
        "X-scope": "*",
        "plat": "2",
        "app": "com.kocom.SmartHome2",
        "app_ver": "1.0.1",
        "X-cliv": "fiid-10.12.0",
        "sender": "444087228688",
        "X-subtype": "444087228688",
        "appid": fid,
        "apns_token": "[**REDACTED**]",
        "gmp_app_id": "1:444087228688:android:1aecd4752f9aec0fd92d95"
    }

    # Asynchronous device registration request
    async with session.post("https://fcmtoken.googleapis.com/register", headers=register_headers, data=register_data) as response:
        if not (fcm_token := await response.text()).startswith("token="):
            raise Exception(response)

    LOGGER.info("Device registration successful. FCM token: %s", fcm_token)
    return fcm_token