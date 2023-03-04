from binascii import hexlify
import x25519

private_key = b'\x00' * 32
public_key = x25519.scalar_base_mult(private_key)
print(int(hexlify(public_key), 16))


