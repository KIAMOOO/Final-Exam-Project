"""
Classical cipher implementations: Caesar and Vigenère
Includes cryptanalysis tools: frequency analysis and Kasiski examination
"""

from collections import Counter
import re
from typing import List, Tuple, Optional


class CaesarCipher:
    """
    Caesar cipher implementation with frequency analysis breaker.
    
    The Caesar cipher is a substitution cipher where each letter is shifted
    by a fixed number of positions in the alphabet.
    """
    
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    @staticmethod
    def encrypt(plaintext: str, shift: int) -> str:
        """
        Encrypt plaintext using Caesar cipher.
        
        Args:
            plaintext: Text to encrypt
            shift: Number of positions to shift (0-25)
            
        Returns:
            Encrypted ciphertext
        """
        shift = shift % 26
        result = []
        
        for char in plaintext.upper():
            if char in CaesarCipher.ALPHABET:
                idx = (CaesarCipher.ALPHABET.index(char) + shift) % 26
                result.append(CaesarCipher.ALPHABET[idx])
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(ciphertext: str, shift: int) -> str:
        """
        Decrypt ciphertext using Caesar cipher.
        
        Args:
            ciphertext: Text to decrypt
            shift: Number of positions to shift (0-25)
            
        Returns:
            Decrypted plaintext
        """
        return CaesarCipher.encrypt(ciphertext, -shift)
    
    @staticmethod
    def frequency_analysis(text: str) -> dict:
        """
        Perform frequency analysis on text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary mapping letters to their frequencies
        """
        text = re.sub(r'[^A-Z]', '', text.upper())
        if not text:
            return {}
        
        counter = Counter(text)
        total = len(text)
        
        return {char: count / total for char, count in counter.items()}
    
    @staticmethod
    def break_cipher(ciphertext: str) -> List[Tuple[int, str, float]]:
        """
        Break Caesar cipher using frequency analysis.
        
        Compares letter frequencies in decrypted text with English letter
        frequencies to find the most likely shift.
        
        Args:
            ciphertext: Encrypted text
            
        Returns:
            List of tuples (shift, decrypted_text, confidence_score)
            sorted by confidence (highest first)
        """
        # English letter frequencies
        english_freq = {
            'E': 0.12702, 'T': 0.09056, 'A': 0.08167, 'O': 0.07507,
            'I': 0.06966, 'N': 0.06749, 'S': 0.06327, 'H': 0.06094,
            'R': 0.05987, 'D': 0.04253, 'L': 0.04025, 'C': 0.02782,
            'U': 0.02758, 'M': 0.02406, 'W': 0.02360, 'F': 0.02228,
            'G': 0.02015, 'Y': 0.01974, 'P': 0.01929, 'B': 0.01492,
            'V': 0.00978, 'K': 0.00772, 'J': 0.00153, 'X': 0.00150,
            'Q': 0.00095, 'Z': 0.00074
        }
        
        results = []
        
        for shift in range(26):
            decrypted = CaesarCipher.decrypt(ciphertext, shift)
            freq = CaesarCipher.frequency_analysis(decrypted)
            
            # Calculate chi-squared statistic
            chi_squared = 0
            text_len = sum(freq.values())
            
            if text_len > 0:
                for letter in CaesarCipher.ALPHABET:
                    observed = freq.get(letter, 0) * text_len
                    expected = english_freq.get(letter, 0) * text_len
                    if expected > 0:
                        chi_squared += ((observed - expected) ** 2) / expected
            
            # Lower chi-squared = better match
            confidence = 1 / (1 + chi_squared)
            results.append((shift, decrypted, confidence))
        
        return sorted(results, key=lambda x: x[2], reverse=True)


class VigenereCipher:
    """
    Vigenère cipher implementation with Kasiski examination breaker.
    
    The Vigenère cipher uses a keyword to shift letters differently
    for each position in the plaintext.
    """
    
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt plaintext using Vigenère cipher.
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key (repeated as needed)
            
        Returns:
            Encrypted ciphertext
        """
        key = key.upper()
        key_len = len(key)
        result = []
        key_idx = 0
        
        for char in plaintext.upper():
            if char in VigenereCipher.ALPHABET:
                shift = VigenereCipher.ALPHABET.index(key[key_idx % key_len])
                idx = (VigenereCipher.ALPHABET.index(char) + shift) % 26
                result.append(VigenereCipher.ALPHABET[idx])
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        """
        Decrypt ciphertext using Vigenère cipher.
        
        Args:
            ciphertext: Text to decrypt
            key: Decryption key
            
        Returns:
            Decrypted plaintext
        """
        key = key.upper()
        key_len = len(key)
        result = []
        key_idx = 0
        
        for char in ciphertext.upper():
            if char in VigenereCipher.ALPHABET:
                shift = VigenereCipher.ALPHABET.index(key[key_idx % key_len])
                idx = (VigenereCipher.ALPHABET.index(char) - shift) % 26
                result.append(VigenereCipher.ALPHABET[idx])
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def find_repeated_sequences(text: str, min_len: int = 3) -> dict:
        """
        Find repeated sequences in text (for Kasiski examination).
        
        Args:
            text: Text to analyze
            min_len: Minimum length of sequences to find
            
        Returns:
            Dictionary mapping sequences to list of positions
        """
        text = re.sub(r'[^A-Z]', '', text.upper())
        sequences = {}
        
        for length in range(min_len, min(len(text) // 2, 10)):
            for i in range(len(text) - length + 1):
                seq = text[i:i+length]
                if seq not in sequences:
                    sequences[seq] = []
                sequences[seq].append(i)
        
        # Filter to only repeated sequences
        return {seq: pos for seq, pos in sequences.items() if len(pos) > 1}
    
    @staticmethod
    def kasiski_examination(ciphertext: str) -> Optional[int]:
        """
        Estimate key length using Kasiski examination.
        
        Finds repeated sequences and calculates GCD of distances
        between occurrences to estimate key length.
        
        Args:
            ciphertext: Encrypted text
            
        Returns:
            Estimated key length (or None if cannot determine)
        """
        import math
        
        sequences = VigenereCipher.find_repeated_sequences(ciphertext)
        
        if not sequences:
            return None
        
        # Calculate distances between repeated sequences
        distances = []
        for seq, positions in sequences.items():
            for i in range(len(positions) - 1):
                distances.append(positions[i+1] - positions[i])
        
        if not distances:
            return None
        
        # Find GCD of distances (simplified: use most common factors)
        # In practice, would use more sophisticated analysis
        factors = {}
        for dist in distances:
            for factor in range(2, min(dist, 20)):
                if dist % factor == 0:
                    factors[factor] = factors.get(factor, 0) + 1
        
        if factors:
            # Return most common factor (likely key length)
            return max(factors.items(), key=lambda x: x[1])[0]
        
        return None
    
    @staticmethod
    def break_cipher(ciphertext: str, max_key_len: int = 10) -> List[Tuple[str, str, float]]:
        """
        Break Vigenère cipher using Kasiski examination and frequency analysis.
        
        Args:
            ciphertext: Encrypted text
            max_key_len: Maximum key length to try
            
        Returns:
            List of tuples (key, decrypted_text, confidence_score)
        """
        # Estimate key length
        estimated_len = VigenereCipher.kasiski_examination(ciphertext)
        
        if estimated_len is None:
            estimated_len = 3  # Default guess
        
        # Try different key lengths around estimate
        key_lengths = [estimated_len]
        for offset in range(1, 3):
            if estimated_len - offset > 0:
                key_lengths.append(estimated_len - offset)
            if estimated_len + offset <= max_key_len:
                key_lengths.append(estimated_len + offset)
        
        results = []
        
        for key_len in key_lengths:
            # Break each column as Caesar cipher
            text = re.sub(r'[^A-Z]', '', ciphertext.upper())
            columns = [''] * key_len
            
            for i, char in enumerate(text):
                columns[i % key_len] += char
            
            # Find best shift for each column
            key_chars = []
            for col in columns:
                if col:
                    best_shift = CaesarCipher.break_cipher(col)[0][0]
                    key_chars.append(CaesarCipher.ALPHABET[best_shift])
            
            key = ''.join(key_chars)
            decrypted = VigenereCipher.decrypt(ciphertext, key)
            
            # Calculate confidence based on frequency analysis
            freq = CaesarCipher.frequency_analysis(decrypted)
            confidence = sum(freq.values())  # Simple confidence metric
            
            results.append((key, decrypted, confidence))
        
        return sorted(results, key=lambda x: x[2], reverse=True)

