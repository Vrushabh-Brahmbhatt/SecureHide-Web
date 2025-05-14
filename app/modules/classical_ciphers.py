"""
Classical ciphers module for SecureHide
Provides implementation of various classical ciphers
"""

class ClassicalCipher:
    """Base class for classical ciphers"""
    
    def encrypt(self, plaintext, key):
        """Base encrypt method"""
        raise NotImplementedError("Subclasses must implement encrypt method")
    
    def decrypt(self, ciphertext, key):
        """Base decrypt method"""
        raise NotImplementedError("Subclasses must implement decrypt method")


class CaesarCipher(ClassicalCipher):
    """Implementation of Caesar Cipher"""
    
    def encrypt(self, plaintext, key):
        """Encrypt plaintext using Caesar cipher with specified shift"""
        try:
            shift = int(key) % 26
        except ValueError:
            raise ValueError("Caesar cipher key must be an integer")
            
        result = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
                result += chr(shifted)
            else:
                result += char
        return result
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using Caesar cipher with specified shift"""
        try:
            shift = int(key) % 26
        except ValueError:
            raise ValueError("Caesar cipher key must be an integer")
            
        # Decryption is just encryption with the negative shift
        return self.encrypt(ciphertext, -shift)


class PlayfairCipher(ClassicalCipher):
    """Implementation of Playfair Cipher"""
    
    def __init__(self):
        self.matrix = []
    
    def _create_matrix(self, key):
        """Create the 5x5 Playfair matrix based on the key"""
        # Remove duplicates from key while preserving order
        key = key.upper().replace('J', 'I')  # Replace J with I as per convention
        key_chars = []
        for char in key:
            if char.isalpha() and char not in key_chars:
                key_chars.append(char)
        
        # Fill remaining matrix with unused alphabet letters
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: J is omitted
        for char in alphabet:
            if char not in key_chars:
                key_chars.append(char)
        
        # Create 5x5 matrix
        self.matrix = []
        for i in range(0, 25, 5):
            self.matrix.append(key_chars[i:i+5])
    
    def _find_position(self, char):
        """Find position of a character in the matrix"""
        char = char.upper()
        if char == 'J':
            char = 'I'
            
        for row in range(5):
            for col in range(5):
                if self.matrix[row][col] == char:
                    return row, col
        return -1, -1
    
    def _prepare_text(self, text):
        """Prepare text for Playfair cipher (handle pairs)"""
        text = text.upper().replace('J', 'I')
        # Keep only alphabetic characters
        text = ''.join(char for char in text if char.isalpha())
        prepared_text = ""
        i = 0
        
        while i < len(text):
            if i == len(text) - 1:
                # If last character, add an 'X'
                prepared_text += text[i] + 'X'
                i += 1
            elif text[i] == text[i+1]:
                # If repeated character, insert an 'X'
                prepared_text += text[i] + 'X'
                i += 1
            else:
                # Normal pair of characters
                prepared_text += text[i] + text[i+1]
                i += 2
        
        return prepared_text
    
    def encrypt(self, plaintext, key):
        """Encrypt plaintext using Playfair cipher with the given key"""
        if not key:
            raise ValueError("Playfair cipher requires a key")
        
        self._create_matrix(key)
        prepared_text = self._prepare_text(plaintext)
        
        ciphertext = ""
        for i in range(0, len(prepared_text), 2):
            char1, char2 = prepared_text[i], prepared_text[i+1]
            row1, col1 = self._find_position(char1)
            row2, col2 = self._find_position(char2)
            
            if row1 == row2:  # Same row
                ciphertext += self.matrix[row1][(col1 + 1) % 5]
                ciphertext += self.matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:  # Same column
                ciphertext += self.matrix[(row1 + 1) % 5][col1]
                ciphertext += self.matrix[(row2 + 1) % 5][col2]
            else:  # Rectangle
                ciphertext += self.matrix[row1][col2]
                ciphertext += self.matrix[row2][col1]
        
        return ciphertext
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using Playfair cipher with the given key"""
        if not key:
            raise ValueError("Playfair cipher requires a key")
        
        self._create_matrix(key)
        ciphertext = ''.join(c for c in ciphertext if c.isalpha()).upper()
        
        plaintext = ""
        for i in range(0, len(ciphertext), 2):
            if i+1 >= len(ciphertext):
                break
                
            char1, char2 = ciphertext[i], ciphertext[i+1]
            row1, col1 = self._find_position(char1)
            row2, col2 = self._find_position(char2)
            
            if row1 == row2:  # Same row
                plaintext += self.matrix[row1][(col1 - 1) % 5]
                plaintext += self.matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:  # Same column
                plaintext += self.matrix[(row1 - 1) % 5][col1]
                plaintext += self.matrix[(row2 - 1) % 5][col2]
            else:  # Rectangle
                plaintext += self.matrix[row1][col2]
                plaintext += self.matrix[row2][col1]
        
        return plaintext


class VigenereCipher(ClassicalCipher):
    """Implementation of Vigenere Cipher"""
    
    def encrypt(self, plaintext, key):
        """Encrypt plaintext using Vigenere cipher with the given key"""
        if not key:
            raise ValueError("Vigenere cipher requires a key")
        
        key = ''.join(c for c in key if c.isalpha()).upper()
        if not key:
            raise ValueError("Vigenere key must contain alphabetic characters")
        
        result = ""
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                # Get the shift from the key character
                key_char = key[key_index % len(key)]
                shift = ord(key_char.upper()) - ord('A')
                
                # Apply the shift
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                result += char
        
        return result
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using Vigenere cipher with the given key"""
        if not key:
            raise ValueError("Vigenere cipher requires a key")
        
        key = ''.join(c for c in key if c.isalpha()).upper()
        if not key:
            raise ValueError("Vigenere key must contain alphabetic characters")
        
        result = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                # Get the shift from the key character
                key_char = key[key_index % len(key)]
                shift = ord(key_char.upper()) - ord('A')
                
                # Apply the negative shift for decryption
                if char.isupper():
                    result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                result += char
        
        return result


class HillCipher(ClassicalCipher):
    """Implementation of Hill Cipher"""
    
    def __init__(self):
        self.block_size = 2  # Using 2x2 matrix for simplicity
    
    def _matrix_mod_inverse(self, matrix, modulus):
        """Calculate the modular inverse of a 2x2 matrix"""
        # For 2x2 matrix [[a, b], [c, d]], det = ad - bc
        det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % modulus
        
        # Check if determinant has an inverse
        det_inv = -1
        for i in range(modulus):
            if (det * i) % modulus == 1:
                det_inv = i
                break
        
        if det_inv == -1:
            raise ValueError("Matrix is not invertible for this key")
        
        # Calculate adjugate matrix and multiply by det_inv
        result = [
            [(matrix[1][1] * det_inv) % modulus, (-matrix[0][1] * det_inv) % modulus],
            [(-matrix[1][0] * det_inv) % modulus, (matrix[0][0] * det_inv) % modulus]
        ]
        
        return result
    
    def _prepare_text(self, text):
        """Prepare text for Hill cipher (ensure length is multiple of block size)"""
        text = ''.join(c for c in text if c.isalpha()).upper()
        
        # Pad with 'X' if necessary
        while len(text) % self.block_size != 0:
            text += 'X'
            
        return text
    
    def _text_to_vectors(self, text):
        """Convert text to list of integer vectors"""
        vectors = []
        for i in range(0, len(text), self.block_size):
            vector = [ord(text[i + j]) - ord('A') for j in range(self.block_size)]
            vectors.append(vector)
        return vectors
    
    def _vectors_to_text(self, vectors):
        """Convert list of integer vectors to text"""
        text = ""
        for vector in vectors:
            for value in vector:
                text += chr(value % 26 + ord('A'))
        return text
    
    def _key_to_matrix(self, key):
        """Convert key string to matrix"""
        key = ''.join(c for c in key if c.isalpha()).upper()
        
        if len(key) < self.block_size * self.block_size:
            raise ValueError(f"Key must have at least {self.block_size * self.block_size} letters")
        
        matrix = []
        for i in range(self.block_size):
            row = []
            for j in range(self.block_size):
                row.append(ord(key[i * self.block_size + j]) - ord('A'))
            matrix.append(row)
        
        return matrix
    
    def encrypt(self, plaintext, key):
        """Encrypt plaintext using Hill cipher with the given key"""
        if not key:
            raise ValueError("Hill cipher requires a key")
        
        # Prepare text and key
        prepared_text = self._prepare_text(plaintext)
        key_matrix = self._key_to_matrix(key)
        
        # Convert text to vectors
        text_vectors = self._text_to_vectors(prepared_text)
        
        # Multiply each vector by the key matrix
        result_vectors = []
        for vector in text_vectors:
            result = [0] * self.block_size
            for i in range(self.block_size):
                for j in range(self.block_size):
                    result[i] = (result[i] + key_matrix[i][j] * vector[j]) % 26
            result_vectors.append(result)
        
        # Convert back to text
        return self._vectors_to_text(result_vectors)
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using Hill cipher with the given key"""
        if not key:
            raise ValueError("Hill cipher requires a key")
        
        # Prepare text and key
        prepared_text = self._prepare_text(ciphertext)
        key_matrix = self._key_to_matrix(key)
        
        # Calculate inverse of key matrix
        try:
            inverse_key = self._matrix_mod_inverse(key_matrix, 26)
        except ValueError as e:
            raise ValueError(f"Cannot decrypt: {str(e)}")
        
        # Convert text to vectors
        text_vectors = self._text_to_vectors(prepared_text)
        
        # Multiply each vector by the inverse key matrix
        result_vectors = []
        for vector in text_vectors:
            result = [0] * self.block_size
            for i in range(self.block_size):
                for j in range(self.block_size):
                    result[i] = (result[i] + inverse_key[i][j] * vector[j]) % 26
            result_vectors.append(result)
        
        # Convert back to text
        return self._vectors_to_text(result_vectors)


# Factory function to get cipher by name
def get_cipher(cipher_type):
    """Get a cipher instance by name"""
    ciphers = {
        'caesar': CaesarCipher(),
        'playfair': PlayfairCipher(),
        'vigenere': VigenereCipher(),
        'hill': HillCipher()
    }
    
    if cipher_type not in ciphers:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")
    
    return ciphers[cipher_type]