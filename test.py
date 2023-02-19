from ellipticcurve.point import Point
from ellipticcurve.curve import prime256v1
from ellipticcurve.math import Math


c = prime256v1

p = Math._toJacobian(Point(
    x=0x440c8c7d996adc6038090e43d8595c45381b840219ea7d376f1fe9cd833bbe61,
    y=0xc5a285ff65319f8f3d8dcb12388457140c00a1887e18a0fe8da0f1b8c34670e3
))

q = Math._toJacobian(Point(
    x=0x7ce1ff2021e6deefb316d445735415e917f1f60c1617e4d21f7671168a1a97f0,
    y=0xaf3f69d7f46758f99b027372b28c20bc8661422698f91de196695f1415a17c8d
))

pp = Math._fromJacobian(Math._jacobianDouble(p, c.A, c.P), c.P)
print(hex(pp.x))
print(hex(pp.y))


p_add_q = Math._fromJacobian(Math._jacobianAdd(p, q, c.A, c.P), c.P)
print(hex(p_add_q.x))
print(hex(p_add_q.y))

p_mul_q = Math._fromJacobian(Math._jacobianMultiply(p, 10, c.N, c.A, c.P), c.P)
print(hex(p_mul_q.x))
print(hex(p_mul_q.y))
