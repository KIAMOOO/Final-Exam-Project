"""
RSA key generation and modular exponentiation from scratch
"""

import secrets
import math
from typing import Tuple


def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """
    Compute (base^exponent) mod modulus using square-and-multiply algorithm.
    
    This is the core operation for RSA encryption/decryption.
    Uses the efficient square-and-multiply method to avoid computing
    large exponentiations directly.
    
    Args:
        base: Base number
        exponent: Exponent
        modulus: Modulus
        
    Returns:
        Result of (base^exponent) mod modulus
    """
    if modulus == 1:
        return 0
    
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result


def miller_rabin(n: int, k: int = 10) -> bool:
    """
    Miller-Rabin primality test.
    
    Probabilistic test to determine if a number is prime.
    Returns True if n is probably prime, False if composite.
    
    Args:
        n: Number to test
        k: Number of test rounds (higher = more accurate)
        
    Returns:
        True if probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Test k times
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = modular_exponentiation(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number of approximately 'bits' bits.
    
    Uses Miller-Rabin test to verify primality.
    
    Args:
        bits: Desired bit length of prime
        
    Returns:
        A prime number
    """
    while True:
        # Generate random odd number
        candidate = secrets.randbits(bits)
        candidate |= 1  # Make odd
        candidate |= (1 << (bits - 1))  # Set MSB
        
        if miller_rabin(candidate):
            return candidate


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm.
    
    Returns (gcd, x, y) such that gcd(a, b) = ax + by.
    Used to find modular inverses.
    
    Args:
        a: First number
        b: Second number
        
    Returns:
        Tuple (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Find modular inverse of a modulo m.
    
    Returns x such that (a * x) mod m = 1.
    
    Args:
        a: Number to find inverse of
        m: Modulus
        
    Returns:
        Modular inverse of a mod m
    """
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m


class RSAKeyGenerator:
    """
    RSA key pair generator.
    
    Generates RSA public/private key pairs using:
    - Prime generation with Miller-Rabin test
    - Modular exponentiation for key operations
    - Extended Euclidean algorithm for inverse calculation
    """
    
    @staticmethod
    def generate_keypair(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA key pair.
        
        Args:
            bits: Bit length for primes (default 1024, gives ~2048-bit n)
            
        Returns:
            Tuple ((public_exponent, modulus), (private_exponent, modulus))
        """
        # Generate two distinct primes
        p = generate_prime(bits)
        q = generate_prime(bits)
        
        # Ensure p != q
        while p == q:
            q = generate_prime(bits)
        
        # Compute modulus
        n = p * q
        
        # Compute Euler's totient function
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent (commonly 65537)
        e = 65537
        while math.gcd(e, phi) != 1:
            e += 2
        
        # Compute private exponent
        d = mod_inverse(e, phi)
        
        # Public key: (e, n)
        # Private key: (d, n)
        public_key = (e, n)
        private_key = (d, n)
        
        return public_key, private_key
    
    @staticmethod
    def encrypt(message: int, public_key: Tuple[int, int]) -> int:
        """
        Encrypt message using RSA public key.
        
        Args:
            message: Message to encrypt (as integer)
            public_key: Public key (e, n)
            
        Returns:
            Encrypted message
        """
        e, n = public_key
        return modular_exponentiation(message, e, n)
    
    @staticmethod
    def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
        """
        Decrypt ciphertext using RSA private key.
        
        Args:
            ciphertext: Encrypted message
            private_key: Private key (d, n)
            
        Returns:
            Decrypted message
        """
        d, n = private_key
        return modular_exponentiation(ciphertext, d, n)

