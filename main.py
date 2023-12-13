import unittest
from ElGamal import randSafePrime, primitiveRoot, keyGen, encrypt, decrypt, digital_sign, verify_auth

class TestElGamal(unittest.TestCase):
    def setUp(self):
        self.p = randSafePrime(128, 256)
        self.g = primitiveRoot(self.p)
        self.private_k, self.public_k = keyGen(self.g, self.p)
        self.test_str = "Hello"

    def test_ElGamalEncryption(self):
        r, s = digital_sign(self.test_str, self.private_k, self.p, self.g)
        res = verify_auth(self.test_str, r, s, self.public_k, self.p, self.g)
        message = "encryption isn't working properly"
        self.assertTrue(res, message)

    def test_ElGamalSigning(self):
        x, y = encrypt(self.test_str, self.public_k, self.g, self.p)
        res = decrypt(x, y, self.private_k, self.p)
        self.assertEqual(self.test_str, res)


if __name__ == '__main__':
    unittest.main()
