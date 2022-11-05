# Spooky RSA

Difficulty:: #easy 

## Introduction
The challenge give us a script that encrypt data using a custom RSA algorithm. But it encrypt the same data two times and use the the `p` prime number inside the data to encrypt. This allow to find `p` with the GCD between de substract of the ciphers and the module `N`.

## Target data
- `File`: ``crypto_spooky_rsa.zip`
``
## Challenge Description
*It was a Sunday evening when, after years, you managed to understand how RSA works. Unfortunately, that changed when the worst villain ever decided to dress up like RSA and scare people who wanted to learn more about cryptography. But his custom uniform has a hole in it. Can you find it?*

## Enumeration
We are given with a python file `chall.py` with a encryption method, and the indication that the `out.txt` file stored the flag encripted and some data of the encryption used.

```shell
magor$ tree crypto_spooky_rsa/
crypto_spooky_rsa/
├── chall.py
└── out.txt
```

### chall.py
At first glance we can see that a [RSA encryption](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is performed (also the challenge tittle and description give us that clue). So probably there is a bad use of the RSA wich we can take advante of decrypt the `out.txt` file. Lets check it out.
```python
# chall.py
# ...SNIP...
def main():
 ➊  N, priv = key_gen(1024)

    m = bytes_to_long(FLAG)

 ➋ (e1, c1), (e2, c2) = encrypt(m, N, priv[0])

    with open('out.txt', 'w') as f:
        f.write(f'N = {N}\n(e1, c1) = ({e1}, {c1})\n(e2, c2) = ({e2}, {c2})\n')


if __name__ == "__main__":
    main()
```

Note that we see how the `out.txt` was made in the `main()` fucntion. first call a custom funtion ➊ to generate `p`,  `q` and `N` , they are needed to perform a RSA encryption, then call ➋ the custom `encrypt()`  function with the Flag `m` and only wth `N` and `p` without using `q` wich is strange.

>**Note**:  if you dont know what are the `p, q, N` generated for  in ➊ , check this resource [Understanding rsa algorithm](https://www.tutorialspoint.com/cryptography_with_python/cryptography_with_python_understanding_rsa_algorithm.htm) There explain the RSA in a clear way.

The general RSA encryption has the following structure:
$$ Message^{e} = cipher \bmod N$$

Where $N = p*q$  ; with  $p$ , $q$ random primes number

Now lets read the `encrypt()` function:

```python
# chall.py
# ...SNIP...
def encrypt(m, N, f):
  ➊ e1, e2 = randint(2, N - 2), randint(2, N - 2)
  ➋ c1 = (pow(f, e1, N) + m) % N
  ➌ c2 = (pow(f, e2, N) + m) % N
    return (e1, c1), (e2, c2)
# ...SNIP...
```

Check that it generate two `e` values ➊ (this also is part of the RSA encryption) and create 2 cipher representation of $m$, one in ➋ with $e_1$ and other in ➌ with $e_2$.

So we have a case with the RSA encryption of the same data with two diferents exponents $e$. Its looks like there will be a vulnerability, but lets see in more detail how the encryption was made written the $c_1$ equation in mathematical notation:
$$ f^{e1} + m = c_1 \bmod N$$

But $f$ we know that is $p$ so replace it in $c_1$ and $c_2$ equations: 
$$
\begin{gather}
p^{e_1} + m = c_1 \bmod N \\
p^{e_2} + m = c_2 \bmod N
\end{gather}
$$

> **Note**: The mathematical notation $a*b = c \bmod n$ can be rewirte in python like `c = a*b%n` 

Its a big mistake use $p$  in this way inside the cipher function. Becase all the RSA encryption at the end consist in that $p$ and $q$ are unknows because they are primes so big that is not possible to think in a bruteforce attack. And remember that $N = p*q$  

## Foothold

Look what happen if we substract $c_1 - c_2$ :
$$ c_1 - c_2 = ((p^{e_1} + m) - (p^{e_2} + m) )\bmod N$$

This cancels $m$:
$$ c_1 - c_2 = (p^{e_1} - p^{e_2})\bmod N$$

It turns into:
$$ c_1 - c_2 = p^{e_1 - e_2}\bmod N$$

So the trick is to note that  both  $p^{e_1 - e_2}$ and $N$ are multiple of $p$. Thats means if we calculate the [GCD](https://en.wikipedia.org/wiki/Greatest_common_divisor)  we will found $P$ .

In Pyhton I use [gmpy2](https://gmpy2.readthedocs.io/en/latest/) library to calculate the  GCD
```python
>>> from gmpy2 import gcd
>>> p = gcd(c1-c2,N)
>>> p
145614687075978061772078778578619196206290620988742519792372104684273419650704368401716821895875185978818467666038442708162317212136824915489933843285926574375531132288848214985723532967694318812537331691288544766294706820729682137162938604475792707762338569477292749632922706975963581600053086970565013829299
```

And with $P$ we can calculate $m$ if we isolate it from equation $c_1$ (or $c_2$) :
$$
p^{e_1} -c_1 = -m \bmod N \\
$$

But, note that if we want remove the negative from $-m$  you have to take into account that In modular aritmethic we can move terms from one side of the equation to another, but it is not the case with factors, we need to multiply by the [**modular multiplicative inverse**](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse). In this case to remove $-1$ . I am gonna call to its modular multiplicative inverse like $neg_{inv}$ :
$$
(p^{e_1} -c_1)*neg_{inv} = m \bmod N
$$

To calculate the modular inverse in Python I use [pycryptodome](https://www.pycryptodome.org/) library

```python
>>> from Crypto.Util.number import inverse
>>> neg_inv = inverse(1,N)
>>> neg_inv
25458200992030509733740123651871827168179694737564741891817013763410533831135578900317404987414083347009443171337016804117994550747038777609425522146275786823385218489896468142658492353321920860029284041857237273061376882168336089921980034356731735024837853873907395117925738744950932927683784527829300499629044776530663084875991411120648155572219472426590747952180037566734905079883718263249789131313731453855593891997376222635496337534679814697188141565730768050813250191975439504290665602928172394124501396491438097237093345376202142503439944034846839870643057174427346860377971316738504003909365471892007511334128
```

So join all together:

```python
# solve.py
from Crypto.Util.number import long_to_bytes, inverse, getStrongPrime, bytes_to_long
from gmpy2 import gcd
import ast

get_from_string = lambda x : x.split('=')[-1].strip()

with open('out.txt', 'r') as f:
    data = f.readlines()

N = int(get_from_string(data[0]))
(e1, c1) = ast.literal_eval(get_from_string(data[1]))
(e2, c2) = ast.literal_eval(get_from_string(data[2]))


p = gcd(c2-c1, N)
neg_inv = inverse(-1,N)

m = ((pow(p,e1,N) - c1 )*(neg_inv))%N

flag = long_to_bytes(int(m))

print(flag)
```


```shell
magor$ python solve.py
b'HTB{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'
```