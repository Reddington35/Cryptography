import cs402 as cs
from cs402 import LFSR

lsfr = LFSR(8,[1,2,3,4,8])
print("State of LSFR: ",lsfr.state)

best_state = lsfr.state # [0,0,0,0,0,0,0,0]
#print(best_state)
max_period = 1

for a in [0,1]:
    for b in [0,1]:
        for c in [0, 1]:
            for d in [0, 1]:
                for e in [0, 1]:
                    for f in [0, 1]:
                        for g in [0, 1]:
                            for h in [0, 1]:
                                period = lsfr.period([a,b,c,d,e,f,g,h])
                                if period > max_period:
                                    max_period = period
                                    best_state = [a,b,c,d,e,f,g,h]
print(max_period)



