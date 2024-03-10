---
layout: post
title: RSA Destroyer 
categories: Write-up FCSC fcsc 2021 cryptography
---

# RSA Destroyer
## Challenge description : 
*This destroyes the RSA cryptosystem.*
## Resolution :
So, we have two files which are : 
1. **output.txt** 
```
e = 65538
n = 444874973852804286630293120525019547982392964519934608680681255396764239795499482860997657663742247333836933457910503642061679607999128792657151145831533603267962151902191791568052924623477918783346790554917615006885807262798511378178431356140169891510484103567017335784087168191133679976921108092647227149255338118895695993606854195408940572577899625236666854544581041490770396755583819878794842828965377818593455075306655077757834318066860484956428681524881285058664687568640627516452658874124048546780999256640377399347893644988620246748059490751348919880389771785423781356133657866769589669296191804649195706447605778549172906037483
c = 95237912740655706597869523108017194269174342313145809624317482236690453533195825723998662803480781411928531102859302761153780930600026069381338457909962825300269319811329312349030179047249481841770850760719178786027583177746485281874469568361239865139247368477628439074063199551773499058148848583822114902905937101832069433266700866684389484684637264625534353716652481372979896491011990121581654120224008271898183948045975282945190669287662303053695007661315593832681112603350797162485915921143973984584370685793424167878687293688079969123983391456553965822470300435648090790538426859154898556069348437896975230111242040448169800372469
```
2. **rsa_destroyer.py**
```python
from Crypto.Util.number import isPrime, bytes_to_long
from Crypto.Random.random import getrandbits

def fastPrime(bits, eps = 32):
  while True:
    a, e, u = getrandbits(eps), getrandbits(eps), getrandbits(4 * eps)
    p = a * (2 ** bits - e) + u
    if isPrime(p):
      return p

def generate(bits = 2048):
  p = fastPrime(bits // 2)
  q = fastPrime(bits // 2)
  return p * q, 2 ** 16 + 1

n, e = generate()

p = bytes_to_long(open("flag.txt", "rb").read())
c = pow(p, e, n)

print(f"e = {e}")
print(f"n = {n}")
print(f"c = {c}")

```
So basically we have two files, the first one contain *n* and *e*  wich are a RSA public key and the python3 script wich create this ouput. We have also *c* which is the ciphertext of the flag.
The most interesting part of this script is this liness :
```python
def fastPrime(bits, eps = 32):
  while True:
    a, e, u = getrandbits(eps), getrandbits(eps), getrandbits(4 * eps)
    p = a * (2 ** bits - e) + u
    if isPrime(p):
      return p
```
It creates a prime number of 1024 bits which is of the form  `a * (2^1024 -e) + u`.
```python
def generate(bits = 2048):
  p = fastPrime(bits // 2)
  q = fastPrime(bits // 2)
  return p * q, 2 ** 16 + 1
```
So we know that it generates 2 primes numbers of 1024 bits and return *n = pq* and *e = 2^16 + 1 = 65537*
However this is not secure because of the structure of *p* and *q*. Explanation :
We have `p = a * (2^1024 -e) + u` and `q = a' * (2^1024 -e') + u'` so 
`n = pq = (a * (2^1024 -e) + u)(a' * (2^1024 -e') + u') = aa'*2^2048 + 2^1024*(a'u +au' -aa'e -aa'e') + aa'ee'-aeu'-a'e'u + uu'`
When we look at *n* given in the file *output.txt* in hex value we have :
*n = bf0a8dd7d8f16cad00[some zeros]
001002c0b6fc6c3c2949b0a1e097f3c51eff2e8919800[some zeros]
00526e422445cbd24c429d60a4a3d75cfd20d09708a2945d9ad2d3b65a55f110eb*
When we look at the form of *n* given just before, we see that `aa' = bf0a8dd7d8f16cad = 13765971169208528045`, `a'u +au' -aa'e -aa'e' = 1002c0b6fc6c3c2949b0a1e097f3c51eff2e89198 = 1462483866390329830822836164002145062407975244184 ` and `aa'ee'-aeu'-a'e'u + uu' = 526e422445cbd24c429d60a4a3d75cfd20d09708a2945d9ad2d3b65a55f110eb = 37284463254120829734596659590852831388840149328402126048476097877596519338219`
So we can deduce a system :
```
aa' = 13765971169208528045
a'u +au' -aa'e -aa'e' = 1462483866390329830822836164002145062407975244184
aa'ee'-aeu'-a'e'u + uu' = 37284463254120829734596659590852831388840149328402126048476097877596519338219
```
Now it's time to us our best friend : sagemath
```python
var('a a2 u u2 e e2') # note that ' is remplaced by 2 (a' = a2)
assume(a, 'integer')
assume(a2, 'integer')
assume(e, 'integer')
assume(e2, 'integer')
assume(u, 'integer')
assume(u2, 'integer')
[solve([13765971169208528045*e*e2-a*e*u2-a2*e2*u+u*u2==37284463254120829734596659590852831388840149328402126048476097877596519338219, a==sol[0], a2==sol[1], a2*u+a*u2-13765971169208528045*e-13765971169208528045*e2==1462483866390329830822836164002145062407975244184], a,a2,e,e2,u,u2) for sol in solve([a*a2==13765971169208528045], a,a2) if sol[0]>0]
# in the last line, we solve a*a2==13765971169208528045 and use all positives solutions to try to solve 13765971169208528045*e*e2-a*e*u2-a2*e2*u+u*u2==37284463254120829734596659590852831388840149328402126048476097877596519338219 and a2*u+a*u2-13765971169208528045*e-13765971169208528045*e2==1462483866390329830822836164002145062407975244184
```
output of script :
```
[some solutions]
 [[a == 3751916785, a2 == 3669050237, e == r199, e2 == r200, u == 3751916785*r199 + 584756716714593367476088089245695598060995702445/3669050237, u2 == 3669050237*r200 + 877727149675736463346748074756449464346979541739/3751916785], [a == 3751916785, a2 == 3669050237, e == r201, e2 == r202, u == 3751916785*r201 + 239224620263965184662787181879747443847, u2 == 3669050237*r202 + 155855460081744155068217508253103646077]],
 [[a == 750383357, a2 == 18345251185, e == r203, e2 == r204, u == 750383357*r203 + 116951343342918673495217617849139119612199140489/3669050237, u2 == 18345251185*r204 + 877727149675736463346748074756449464346979541739/750383357], [a == 750383357, a2 == 18345251185, e == r205, e2 == r206, u == 750383357*r205 + 239224620263965184662787181879747443847/5, u2 == 18345251185*r206 + 779277300408720775341087541265518230385]]]
```
And here we have our solution !
`[a == 3751916785, a2 == 3669050237, e == r201, e2 == r202, u == 3751916785*r201 + 239224620263965184662787181879747443847, u2 == 3669050237*r202 + 155855460081744155068217508253103646077]`
It's the good solution because all other solutions contain non integer values like `u == 750383357*r205 + 239224620263965184662787181879747443847/5`.
Now we know that `a = 3751916785` and `a' =  3669050237`. An other thing that the solution tells us is that *e* and *e'* can be random values if we calculate *u* and *u'* by the way that he provided to us.
I chose *e=1* and *e2=1*. I solve this same equation but now I have *a*, *a'*, *e* and *e'* with sage:
```python
solve([a == 3751916785, a2 == 3669050237, u == 3751916785*e + 239224620263965184662787181879747443847, u2 == 3669050237*e2 + 155855460081744155068217508253103646077, a2*u+a*u2-13765971169208528045*e-13765971169208528045*e2==1462483866390329830822836164002145062407975244184, e==1,e2==1], a,a2,e,e2,u,u2)
```
output :`[[a == 3751916785, a2 == 3669050237, e == 1, e2 == 1, u == 239224620263965184662787181883499360632, u2 == 155855460081744155068217508256772696314]]`
I calculate 
```
p = a * (2^1024 -e) + u = 3751916785*(2**1024 - 1) + 239224620263965184662787181883499360632 = 674479504696919171818209138170896929184144160503723157685764656019609458897622458911275118577732691008132669767000954379937521636401079275913922817460366250826125040174843950575328660454671227442465816947925083890925687493439889603241440139069690138898350567875821173147474029551344349606413915259235906464902601014407
```
A little verification with sage and we obtain: 
```
n%674479504696919171818209138170896929184144160503723157685764656019609458897622458911275118577732691008132669767000954379937521636401079275913922817460366250826125040174843950575328660454671227442465816947925083890925687493439889603241440139069690138898350567875821173147474029551344349606413915259235906464902601014407=0
```
which mean that `n` can be divided by our value so our value is a factor of `n`.
We compute 
```
q = 659582642251985314362307734210980141587990030204881394001744413074708308546817474685792301171688495448876790836409125328438208366401710517774121396192603597603616766901493450446136669311578027124303640315728150060301983975690325150435563807547229372690246398941352389804231125578232145988030672542255427199846588966269
```
Now that we have *p* and *q* we can compute *d* with python3:
```python
q = 659582642251985314362307734210980141587990030204881394001744413074708308546817474685792301171688495448876790836409125328438208366401710517774121396192603597603616766901493450446136669311578027124303640315728150060301983975690325150435563807547229372690246398941352389804231125578232145988030672542255427199846588966269
p = 674479504696919171818209138170896929184144160503723157685764656019609458897622458911275118577732691008132669767000954379937521636401079275913922817460366250826125040174843950575328660454671227442465816947925083890925687493439889603241440139069690138898350567875821173147474029551344349606413915259235906464902601014407
n = p*q
e = 2**16+1
phi_n = (p-1) * (q-1)
d = pow(e,-1,phi_n) # d = e^-1 mod phi_n
c = 95237912740655706597869523108017194269174342313145809624317482236690453533195825723998662803480781411928531102859302761153780930600026069381338457909962825300269319811329312349030179047249481841770850760719178786027583177746485281874469568361239865139247368477628439074063199551773499058148848583822114902905937101832069433266700866684389484684637264625534353716652481372979896491011990121581654120224008271898183948045975282945190669287662303053695007661315593832681112603350797162485915921143973984584370685793424167878687293688079969123983391456553965822470300435648090790538426859154898556069348437896975230111242040448169800372469
from Crypto.Util.number import long_to_bytes
decrypted = pow(c,d,n)
flag = long_to_bytes(decrypted)
print(flag) #FCSC{...}
```