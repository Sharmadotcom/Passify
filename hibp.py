import hashlib
import requests


def check_pwned(password: str) -> int:
    """
    Check a password against the HaveIBeenPwned Pwned Passwords API
    using k-anonymity (only the first 5 chars of the SHA1 hash are sent).

    Returns:
        int >= 0  — number of times the password appeared in known breaches
        int == -1 — API was unreachable (treat as unknown, don't block user)
    """

    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:

        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "Passify-PasswordManager"},
            timeout=5
        )
        response.raise_for_status()

    except requests.RequestException:
        # API unavailable — fail open so the user isn't blocked
        return -1

    # Each line is "HASH_SUFFIX:COUNT"
    for line in response.text.splitlines():

        hash_suffix, _, count = line.partition(":")

        if hash_suffix == suffix:
            return int(count)

    return 0
