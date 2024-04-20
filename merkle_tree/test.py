import numpy as np

num = [15375052760035146755, 14123160272647235780, 18083207111578840050, 2621846622485811624, 0 ]
lc1=0
e2 = 10

for i in range(len(num)):
    lc1 = lc1 + num[i] * e2
    e2 = e2 + e2
    
print(lc1)