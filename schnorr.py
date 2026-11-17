import secrets
from number_theory import modpow, modinv
from group import in_subgroup


def keygen(group):

    p, q, g = group
    x=secrets.randbelow(q-2)+1
    y=modpow(g,x,p)
    return x,y
  


class Prover:


    def __init__(self, group, x):
        self.p, self.q, self.g = group
        self.x = x
        self.r = None

    def commit(self):

        self.r=secrets.randbelow(self.q-1)+1
        return modpow(self.g,self.r,self.p)
        

    def respond(self, c):

        s=(self.r +c*self.x)%self.q
        return s
        


class Verifier:
 

    def __init__(self,group, y):
        self.p, self.q, self.g = group
        self.y = y
        self.c = None

    def challenge(self):

        self.c=secrets.randbelow(self.q)
        return self.c
       

    def check(self, t, s):

        if not in_subgroup(t,self.p,self.q):
            return False
        if s<0 or s>=self.q:
            return False
        return modpow(self.g,s,self.p)==t * modpow(self.y, self.c, self.p) % self.p  
        


def extract_secret(group, c1, s1, c2, s2):

    p,q,g=group
    numerator=(s1-s2)%q
    inverse=modinv((c1-c2)%q,q)
    return numerator * inverse % q            
   


def simulate(group, y):

    p, q, g = group
    c = secrets.randbelow(q)
    s = secrets.randbelow(q)
    t = modpow(g, s, p) * modpow(y, q - c, p) % p
    return t, c, s
    
