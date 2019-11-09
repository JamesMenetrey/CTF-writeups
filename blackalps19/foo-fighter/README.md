# Foo Fighter
```
Category: Reverse engineering
Author: Testeur de stylos
Completed by: Jämes Ménétrey
Operating system: Linux
Tools: IDA Pro
Flag: BA19{You'rE_@_Pen(C1l)_T3stEr!}
```



## Description
What are these holy shits ?! Give me a password and I will maybe give you a flag ! Don't you trust me ? As they said, There is nothing left to lose !



## Solution
The given file is an assembly listing (`challenge/foo_fighter.asm`) that can be compiled using nasm:

```
nasm -f elf32 main_fighter.asm  && ld main_fighter.o -o main_fighter -m elf_i386 -e main -dynamic-linker /lib/ld-linux.so.2 -lc
```



### Retrieving the serial
The execution of the binary leads to this message:

> Mutter! Mutter! Gib mir arg!
>
> ./prog \<key\>

The assembly has a lot of symbols that are called `foo` with variations in name case and substitutions of letters by numbers. IDA Pro has been used to rename the symbols with more describing identifiers and annotate each step of the serial check (`solution/annotated_assembly.asm`). The serial check can be found in the routine named `check_key` and is formed by a series of verification of the characters of the key. As soon as one check fails, the control flow is routed to the `wrong_key` label, showing the message that the serial is not valid.

The serial is a string of 16 characters. It has been reconstructed using a Scala script that applies the required constraints:

```scala
val serialCharset = '0' to '9' union('A' to 'Z') union('a' to 'z')

def shake(a1: Char, a2: Int): Boolean = {
  val v3 = (a1 & 0xF0) >> 4
  v3 == (a1 & 0xF) && v3 == a2
}

def bruteForceShake(a2: Int): Char = {
  val r = for (c <- serialCharset if shake(c, a2)) yield c
  r.head
}

def bruteForce5thAnd11th(): (Char, Char) = {
  val r = for {
    c1 <- serialCharset
    c2 <- serialCharset
    if (c1 ^ c2) == 0x1b
    if (c1 + c2) == 0xa3
    if (c2 - c1) == 5
  } yield (c1, c2)

  r.head
}

object SerialChars {
  val (_5, _11) = bruteForce5thAnd11th()

  lazy val _0 = _2 - 0x20
  lazy val _1 = '0'
  lazy val _2 = bruteForceShake(7)
  lazy val _3 = '_'
  lazy val _4 = bruteForceShake(6)
  lazy val _6 = _1
  lazy val _7 = _4 - 0x20
  lazy val _8 = 1 + 0x30
  lazy val _9 = _10 - 1
  lazy val _10 = _4 + 2
  lazy val _12 = 3 + 0x30
  lazy val _13 = 'r'
  lazy val _14 = (1 << 5) + 1
  lazy val _15 = _14
}

import SerialChars._

val serial = 
  Array(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15)
  .map(_.toChar)
  .mkString("")

println(s"The serial is: $serial")
```

The script prints `The serial is: W0w_fO0F1ghT3r!!`. Once the key is supplied to the executable, the following output is returned:

> Exec me: (without quotes and  with \x0a as carriage return)
> 
>'jAX<At BA19{\*\*\*_surely_not_a_flag_\*\*\*}
>
>[[T[CCCCCCCCCSXXXXX54id+5G,;SPXX5kMli5j}ALPXX5l|Il5_UslPXX5zb;d5=UUiPXX5Lgi$5:^QvPXX5ii265}B]nPXX5mi;k5fi10P>>>>'



### Retrieving the flag
The string provided by the executable is a self-modifying shellcode. The easiest way to execute it is to inject it to an executable stack and inserting a breakpoint at the end to recover the flag. For that purpose, a C program has been written.

Firstly, the string is converted to hex values and inserted in an array, with an additional `INT3` instruction (0xCC) in order to break the execution of the debugger, enabling the dumping of the flag from the memory. Secondly, a pointer of the stack is retrieved and the content of the stack is overwritten by the shellcode. Finally, the control flow is moved to the stack.

NOTE: an additional `push 0x90909090` has been required to align the self-modifications of the shellcode with the embedded flag.

```C
#include <stdio.h>

int main()
{
	unsigned char shellcode[] = { 0x6a, 0x41, 0x58, 0x3c, 0x41, 0x74, 0x20, 0x42, 0x41, 0x31, 0x39, 0x7b, 0x2a, 0x2a, 0x2a, 0x5f, 0x73, 0x75, 0x72, 0x65, 0x6c, 0x79, 0x5f, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x5f, 0x66, 0x6c, 0x61, 0x67, 0x5f, 0x2a, 0x2a, 0x2a, 0x7d, 0x0a, 0x5b, 0x5b, 0x54, 0x5b, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x53, 0x58, 0x58, 0x58, 0x58, 0x58, 0x35, 0x34, 0x69, 0x64, 0x2b, 0x35, 0x47, 0x2c, 0x3b, 0x53, 0x50, 0x58, 0x58, 0x35, 0x6b, 0x4d, 0x6c, 0x69, 0x35, 0x6a, 0x7d, 0x41, 0x4c, 0x50, 0x58, 0x58, 0x35, 0x6c, 0x7c, 0x49, 0x6c, 0x35, 0x5f, 0x55, 0x73, 0x6c, 0x50, 0x58, 0x58, 0x35, 0x7a, 0x62, 0x3b, 0x64, 0x35, 0x3d, 0x55, 0x55, 0x69, 0x50, 0x58, 0x58, 0x35, 0x4c, 0x67, 0x69, 0x24, 0x35, 0x3a, 0x5e, 0x51, 0x76, 0x50, 0x58, 0x58, 0x35, 0x69, 0x69, 0x32, 0x36, 0x35, 0x7d, 0x42, 0x5d, 0x6e, 0x50, 0x58, 0x58, 0x35, 0x6d, 0x69, 0x3b, 0x6b, 0x35, 0x66, 0x69, 0x31, 0x30, 0x50, 0x3e, 0x3e, 0x3e, 0x3e, 0xcc};

	unsigned char* stack;
	asm("mov %0, esp": "=m"(stack));
	
	for(int i = 0; i < sizeof(shellcode); i++) stack[i] = shellcode[i];

	asm("push 0x90909090; call esp");
    
    return 0;
}
```

The program is compiled in 32-bit with an executable stack:

```
gcc shellcode-executor.c -masm=intel -m32 -z execstack -o shellcode-executor
```

Before the execution of the shellcode, the stack looks like as follows:

![Stack before](https://github.com/ZenLulz/ctf-writeups/raw/master/blackalps19/foo-fighter/solution/stack-before.png)

After the execution of the shellcode (when the INT3 breaks the execution of the debugger), the stack looks like as follows:

![Stack before](https://github.com/ZenLulz/ctf-writeups/raw/master/blackalps19/foo-fighter/solution/stack-after.png)

The flag is: **BA19{You'rE_@_Pen(C1l)_T3stEr!}**.