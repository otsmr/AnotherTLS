from ellipticcurve.point import Point
from ellipticcurve.curve import prime256v1
from ellipticcurve.math import Math
from ellipticcurve.ecdsa import Ecdsa, Signature
from ellipticcurve.privateKey import PrivateKey


c = prime256v1


def generate_math_test_values():
    p = Math._toJacobian(Point(
        x=0x440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61,
        y=0xc5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3
    ))

    q = Math._toJacobian(Point(
        x=0x7ce1ff2021e6deefb316d445735415e917f1f60c1617e4d21f7671168a1a97f0,
        y=0xaf3f69d7f46758f99b027372b28c20bc8661422698f91de196695f1415a17c8d
    ))

    pp = Math._fromJacobian(Math._jacobianDouble(p, c.A, c.P), c.P)
    print(pp.x)
    print(pp.y)


    p_add_q = Math._fromJacobian(Math._jacobianAdd(p, q, c.A, c.P), c.P)
    print(p_add_q.x)
    print(p_add_q.y)

    p_mul_q = Math._fromJacobian(Math._jacobianMultiply(p, 10, c.N, c.A, c.P), c.P)
    print(p_mul_q.x)
    print(p_mul_q.y)


def generate_ecdsa_test_values():

    # openssl ecparam -name secp256r1 -genkey -out privateKey.pem
    privateKey = PrivateKey.fromPem("""
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIE1ez4qzSxgjMkGXbrCbFLJQe6L2DtbAMwt8IjDIBvIIoAoGCCqGSM49
AwEHoUQDQgAEf3T+lqd3RkrASp207zV1qzmOUBwOwEHfjvqKQhOOukxb0EedtqVO
oKaJ6oa7uQzf6oHFduTJYFdg1023xsSTpQ==
-----END EC PRIVATE KEY-----
    """)

    print("secret =", hex(privateKey.secret))


    print(privateKey.curve.name)


    print("! randNum must be 10")
    signature = Ecdsa.sign("Hallo Welt!", privateKey)
    sig = Signature(r=0x1afe1e42d4f34a3a0627d62ec5cf4273f1f5206270d3ddf82d2dc26260b82149, s=0x68609a5763ab7ff23b6ef31ba966fa437ed54fb44f95786d1bfbb9c554b0fa6e)
    print(sig.toDer().hex())
    print("r =", hex(signature.r))
    print("s =", hex(signature.s))
    print(signature.toDer().hex())


# 3045022100dc1718b7ac12eb9d2a3db6f05f819d0d4cb668e4802f60aa082d97e2e6e4432f 02206f42f518093352c3e6a61f340629a4a35788eeb7dc34417b4cb1ec0a64781c7b
# 3042 22   dc1718b7ac12eb9d2a3db6f05f819d0d4cb668e4802f60aa082d97e2e6e4432f  22 6f42f518093352c3e6a61f340629a4a35788eeb7dc34417b4cb1ec0a64781c7b

generate_ecdsa_test_values()
# generate_math_test_values()
