import secrets
import string

def generate_password(length=16):

    characters = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    return ''.join(
        secrets.choice(characters)
        for _ in range(length)
    )