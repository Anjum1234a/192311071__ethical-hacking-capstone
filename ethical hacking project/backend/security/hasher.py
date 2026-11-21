import re
import hmac
import bcrypt

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    HAS_ARGON2 = True
    argon2_hasher = PasswordHasher(
        time_cost=2,
        memory_cost=65536,  # 64 MB
        parallelism=2,
        hash_len=32,
        salt_len=16
    )
except ImportError:
    HAS_ARGON2 = False
    argon2_hasher = None

class PasswordSecurityService:
    """
    Module 1: Adaptive User Authentication & Login Management
    Authentication Security Subsystem
    
    Enterprise-Grade Password Hashing & Verification Engine:
    - Primary: Argon2id (Memory-hard against ASIC & GPU cracking)
    - Fallback/Secondary: Bcrypt (Blowfish-based with cost factor 12)
    - Timing-Attack Resistant Verification
    """

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Enforces strong password policy."""
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter (A-Z)."
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter (a-z)."
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one numerical digit (0-9)."
        if not re.search(r'[^A-Za-z0-9]', password):
            return False, "Password must contain at least one special symbol (!@#$%^&*)."
        return True, "Password meets security strength requirements."

    @staticmethod
    def hash_password(plain_password: str, prefer_argon2: bool = True) -> str:
        """
        Cryptographically hashes plain text password.
        Never stores plain text passwords in memory or disk.
        """
        if prefer_argon2 and HAS_ARGON2:
            return argon2_hasher.hash(plain_password)
        
        # Bcrypt implementation with 12 salt rounds
        salt = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
        return hashed_bytes.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Validates password against hash.
        Supports both Argon2 and Bcrypt hashes automatically.
        """
        if not plain_password or not hashed_password:
            return False

        try:
            # Check if hash is Argon2 format ($argon2...)
            if hashed_password.startswith('$argon2'):
                if HAS_ARGON2:
                    try:
                        return argon2_hasher.verify(hashed_password, plain_password)
                    except VerifyMismatchError:
                        return False
                return False

            # Check if hash is Bcrypt format ($2b$, $2a$, $2y$)
            elif hashed_password.startswith(('$2b$', '$2a$', '$2y$')):
                return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

            # Fallback constant-time string comparison (defense against timing attacks)
            return hmac.compare_digest(plain_password, hashed_password)
        except Exception:
            return False

password_service = PasswordSecurityService()

