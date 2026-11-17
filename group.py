
import secrets
from number_theory import generate_safe_prime, modpow


def generate_group(bits=64):

    p=generate_safe_prime(bits)
    q=(p-1)//2
    a=1
    while True :
        h=secrets.randbelow(p-3)+2
        g=modpow(h,2,p)
        if g!=1:
            return p,q,g


    


def in_subgroup(y, p, q):
    return y>1 and y<p and modpow(y,q,p)==1
    
