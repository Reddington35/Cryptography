import itertools
import cs402 as cs

plain_text  = [0,0,0,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,1,1,0,1,0,1,1,0,1,1,0,1]
cypher_text = [1,1,1,1,0,0,0,0,0,1,0,0,0,1,1,0,0,1,1,1,0,0,0,0,1,0,0,1,1,1]
key = []
for i in range(len(plain_text)):
    ans = (plain_text[i] + cypher_text[i]) % 2
    key.append(ans)
print(key)

states = key[0:16]
print(states)

L = 8
A = []

for i in range(8,16):
    eq = states[i - L:i]
    eq.reverse()
    A.append(eq)
print(A)

B = states[8:16]

M = 2
co_ef = cs.solve_modular_linear_system(A,B,M)
print("This is co-ef",co_ef)

# [2,4,5,6,7,8]

lfsr = cs.LFSR(8,[2,4,5,6,7,8])
stream = cs.StreamCipher(lfsr)
print(stream.encrypt_bit_string(key[0:8],plain_text))

if stream.encrypt_bit_string(key[0:8],plain_text) == cypher_text:
    print("found")











