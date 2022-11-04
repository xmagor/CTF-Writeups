# Gonna Lift Em All

Difficulty:: #easy

## Introduction
We are given a script that performs a custom encryption and a file with the encrypted. Its a bad implementation of a asymetric encryption that allow to the attack reverse the encyption because operation with terms (sum) and factors (multiplication) can be reveresed in modular arithmetic, unlike exponentiation.

## Target data
- `File` :  `crypto_gonna-lift-em-all.zip`

## Challenge Description

*Quick, there's a new custom Pokemon in the bush called "The Custom Pokemon". Can you find out what its weakness is and capture it?*

## Enumeration

We are given with a python file  `chall.py` with a encryption method, and the indication that the `data.txt` file stored the flag encripted and some data of the encryption used. 

```shell
magor$ tree gonna-lift-em-all/
gonna-lift-em-all/
├── chall.py
└── data.txt
```

### chall.py

At first glance, the crypto system presented is an atempt of asymetric key encryption, but it doesn't well implemented because it doesn't use the private key, instead , use the publick key to encrypt the flag.
```python
# gonna-lift-em-all/chall.py

from Crypto.Util.number import bytes_to_long, getPrime
import random

FLAG = b'HTB{??????????????????????????????????????????????????????????????????????}'

def gen_params():
  p = getPrime(1024)
  g = random.randint(2, p-2)
  x = random.randint(2, p-2)
  h = pow(g, x, p)
  return (p, g, h), x

def encrypt(pubkey):
  p, g, h = pubkey
  m = bytes_to_long(FLAG)
  y = random.randint(2, p-2)
  s = pow(h, y, p)
  return (g * y % p, m * s % p)



def main():
  pubkey, privkey = gen_params()
  c1, c2 = encrypt(pubkey)

  with open('data.txt', 'w') as f:
    f.write(f'p = {pubkey[0]}\ng = {pubkey[1]}\nh = {pubkey[2]}\n(c1, c2) = ({c1}, {c2})\n')


if __name__ == "__main__":
  main()
```

Analizing the crypto system I list the whole variables to check where is know and where is missing in the `data.txt` file:

| variable | know | Definition               |
| -------- | ---- | ------------------------ |
| p        | Yes  | `getPrime(1024)`         |
| g        | Yes  | `random.randint(2, p-2)` |
| x        | No   | `random.randint(2, p-2)` |
| h        | Yes  | `pow(g, x, p)`           |
| m        | No   | FLAG                     |
| y        | No   | `random.randint(2, p-2)` |
| s        | No   | `pow(h, y, p)`           |
| c1       | Yes  | `g * y % p`              |
| c2       | Yes  | `m * s % p`              |

Look that `c2` is the encrypted representation of the flag  (`m` value), and the fact that the private key is not use it seems that maybe is possible reverse the encryption. So lets write the `c2` equation in modular notation: $$m*s = c_2 \bmod p$$

In modular aritmethic we can move terms from one side of the equation to another, but it is not the case with factors, we need to multiply by the [inverse modular](). so the inverse modular of $m$ is written  $m^{-1}$  Knowing that, we can clear  $m^{-1}$  $$c_2^{-1}*s = m^{-1}\bmod p$$
So we need is calculate `s` and the inverse modular of `c2`. 

To calculate `s` we can use the definition. $$h*y = s\bmod p$$

Althougth we dont know `y` , but we can use `c1` to calcultate `y`. $$g*y = c_1 \bmod p$$

Solving the equation we can calculate the inverse modular of`y`. $$g*c_1^{-1} = y^{-1} \bmod p$$

Now we can calculate the inverse modular of $y^{-1}$  to obtain $y$ . Then calculate $s$ and with $s$   
and $c_2^{-1}$  calculated $m^{-1}$. To finalize calcuolating the inverse modular of $m^{-1}$ to obtain $m$.

> 1. To calculate the $x^{-1}$ ( the inverse modular of $x$ ) we can use the module `pycripto` :[Crypto.Util.number.inverse method]() in Python3
> 2. The notation $a*b = c \bmod n$ can be rewirte in python like `c = a*b%n`

To install `pycrypto` only have to verify the python version:

```shell
# python < 3.8 
pip install pycrypto
#python >= 3.8
pip install pycryptodome
```

So join togheter all the equations:

```python
# solve.py

from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse
import ast

get_from_string = lambda x : x.split('=')[-1].strip()

with open('data.txt', 'r') as f:
    data = f.readlines()

p = int(get_from_string(data[0]))
g = int(get_from_string(data[1]))
h = int(get_from_string(data[2]))
c1, c2 = ast.literal_eval(get_from_string(data[3]))


c1_inver = inverse(c1,p)
y_inv = g*c1_inver%p

y = inverse(y_inv,p)
s = pow(h, y, p)

c2_inver = inverse(c2,p)
m_inver = s*c2_inver%p

m = inverse(m_inver,p)

print(long_to_bytes(m))
```

```shell
> python solve.py
b'HTB{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'
```


## Notes
I search [crypto p g x h c1 c2 pubkey encryption](https://www.google.com/search?client=firefox-b-d&q=crypto+p+g+x+h+c1+c2+pubkey+encryption) and with I found I assume the try implement the [ElGamal Encryption](https://www.tutorialspoint.com/cryptography/public_key_encryption.htm).


