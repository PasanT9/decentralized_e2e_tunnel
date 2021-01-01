import random
execfile('mini_ecdsa.py')


# Public Parameters
q = 7
C = CurveOverFp(2, 0, 1, q)
print("points: ", C.show_points())

P = Point(0, 1)
s = 4
Pub = C.mult(P, s)
print(Pub)

# Key Generation
r = [None] * 4
K = [None] * 4
h = [None] * 4
Sk = [None] * 4
x = [None] * 4
Pk = [None] * 4

for i in range(4):
    r[i] = random.randint(1, q)
    K[i] = C.mult(P, r[i])
    h[i] = random.randint(1, q)
    Sk[i] = r[i] + h[i]*s

    #print(C.mult(P, Sk[i]))
    #print(C.add(C.mult(Pub, h[i]), K[i]))

    x[i] = random.randint(1, q)
    Pk[i] = C.mult(P, x[i])


def addZeros(strr, n):
    for i in range(n):
        strr = "0" + strr
    return strr


def getXOR(a, b):

    # Lengths of the given strrings
    aLen = len(a)
    bLen = len(b)

    # Make both the strrings of equal lengths
    # by inserting 0s in the beginning
    if (aLen > bLen):
        b = addZeros(b, aLen - bLen)
    elif (bLen > aLen):
        a = addZeros(a, bLen - aLen)

    # Updated length
    lenn = max(aLen, bLen)

    # To store the resultant XOR
    res = ""
    for i in range(lenn):
        if (a[i] == b[i]):
            res += "0"
        else:
            res += "1"

    return res


# Ring Signature
Signer = 2
Receiver = 3
rand = random.randint(1, q)

m = "Hello"
m_bin = ' '.join(format(ord(x), 'b') for x in m)

print("Signing")
R0 = C.mult(P, rand)
R = C.mult(Pk[Receiver], rand)
l = R
l_bin = str(l)

C1 = getXOR(m_bin, l_bin)
print(C1)

R = [Point]*4
R[0] = Point(0, 1)
R[1] = Point(1, 5)
R[2] = Point(6, 3)
R[3] = Point(6, 4)
t = [None]*4

for i in range(4):
    t_0 = C.add(C.add(C.add(K[i], Pk[i]), R[i]), R0)
    t_1 = str(t_0) + m
    t_2 = 0
    for j in range(len(t_1)):
        t_2 = t_2 + ord(t_1[i])
    t[i] = (t_2 % (q-1))+1
    print(t[i])

rs = 4
