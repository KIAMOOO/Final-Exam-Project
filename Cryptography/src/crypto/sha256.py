"""
Simplified SHA-256 implementation from scratch
Note: This is a simplified version for educational purposes.
For production, use the cryptography library's SHA-256.
"""

import struct


class SHA256:
    """
    Simplified SHA-256 hash function implementation.
    
    This implementation demonstrates the core SHA-256 algorithm:
    - Message padding
    - Block processing
    - Hash computation
    
    Note: This is simplified and may not handle all edge cases.
    For production use, prefer the standard library's hashlib.sha256.
    """
    
    # SHA-256 constants
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66b, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    @staticmethod
    def _right_rotate(value, amount):
        """Right rotate a 32-bit value"""
        return ((value >> amount) | (value << (32 - amount))) & 0xffffffff
    
    @staticmethod
    def _chunk_message(message):
        """Break message into 512-bit chunks"""
        chunk_size = 64
        return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
    
    @staticmethod
    def _pad_message(message_bytes):
        """Pad message according to SHA-256 specification"""
        message_len = len(message_bytes)
        bit_len = message_len * 8
        
        # Append 0x80 byte
        padded = bytearray(message_bytes)
        padded.append(0x80)
        
        # Append zeros until length is 448 mod 512
        while len(padded) % 64 != 56:
            padded.append(0x00)
        
        # Append original length as 64-bit big-endian
        padded.extend(struct.pack('>Q', bit_len))
        
        return bytes(padded)
    
    @staticmethod
    def hash(message):
        """
        Compute SHA-256 hash of message.
        
        Args:
            message: Input message (bytes or str)
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        
        # Pad message
        padded = SHA256._pad_message(message_bytes)
        
        # Initialize hash values
        h = list(SHA256.H0)
        
        # Process each 512-bit chunk
        chunks = SHA256._chunk_message(padded)
        
        for chunk in chunks:
            # Create message schedule
            w = list(struct.unpack('>16I', chunk))
            w.extend([0] * 48)
            
            # Extend the first 16 words into the remaining 48 words
            for i in range(16, 64):
                s0 = SHA256._right_rotate(w[i-15], 7) ^ SHA256._right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
                s1 = SHA256._right_rotate(w[i-2], 17) ^ SHA256._right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
                w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
            
            # Initialize working variables
            a, b, c, d, e, f, g, h0 = h
            
            # Main loop
            for i in range(64):
                S1 = SHA256._right_rotate(e, 6) ^ SHA256._right_rotate(e, 11) ^ SHA256._right_rotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h0 + S1 + ch + SHA256.K[i] + w[i]) & 0xffffffff
                S0 = SHA256._right_rotate(a, 2) ^ SHA256._right_rotate(a, 13) ^ SHA256._right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xffffffff
                
                h0 = g
                g = f
                f = e
                e = (d + temp1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xffffffff
            
            # Add compressed chunk to hash
            h[0] = (h[0] + a) & 0xffffffff
            h[1] = (h[1] + b) & 0xffffffff
            h[2] = (h[2] + c) & 0xffffffff
            h[3] = (h[3] + d) & 0xffffffff
            h[4] = (h[4] + e) & 0xffffffff
            h[5] = (h[5] + f) & 0xffffffff
            h[6] = (h[6] + g) & 0xffffffff
            h[7] = (h[7] + h0) & 0xffffffff
        
        # Produce final hash
        return ''.join(f'{x:08x}' for x in h)

