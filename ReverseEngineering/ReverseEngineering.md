# Reverse Engineering

### vault-door-training (50 points)

Your mission is to enter Dr. Evil's laboratory and retrieve the blueprints for his Doomsday Project. The laboratory is protected by a series of locked vault doors. Each door is controlled by a computer and requires a password to open. Unfortunately, our undercover agents have not been able to obtain the secret passwords for the vault doors, but one of our junior agents obtained the source code for each vault's computer! You will need to read the source code for each level to figure out what the password is for that vault door. As a warmup, we have created a replica vault in our training facility. The source code for the training vault is here: `VaultDoorTraining.java`

FLAG: `picoCTF{w4rm1ng_Up_w1tH_jAv4_c0b141c5e30}`

```java
import java.util.*;

class VaultDoorTraining {
    public static void main(String args[]) {
        VaultDoorTraining vaultDoor = new VaultDoorTraining();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // The password is below. Is it safe to put the password in the source code?
    // What if somebody stole our source code? Then they would know what our
    // password is. Hmm... I will think of some ways to improve the security
    // on the other doors.
    //
    // -Minion #9567
    public boolean checkPassword(String password) {
        return password.equals("w4rm1ng_Up_w1tH_jAv4_c0b141c5e30");
    }
}

```

### vault-door-1 (100 points)

This vault uses some complicated arrays! I hope you can make sense of it, special agent. The source code for this vault is here: `VaultDoor1.java`

FLAG: `picoCTF{d35cr4mbl3_tH3_cH4r4cT3r5_03f841}`

```java
import java.util.*;

class VaultDoor1 {
    public static void main(String args[]) {
        VaultDoor1 vaultDoor = new VaultDoor1();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(), userInput.length() - 1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // I came up with a more secure way to check the password without putting
    // the password itself in the source code. I think this is going to be
    // UNHACKABLE!! I hope Dr. Evil agrees...
    //
    // -Minion #8728
    public boolean checkPassword(String password) {
        return password.length() == 32 &&
            password.charAt(0) == 'd' &&
            password.charAt(29) == '8' &&
            password.charAt(4) == 'r' &&
            password.charAt(2) == '5' &&
            password.charAt(23) == 'r' &&
            password.charAt(3) == 'c' &&
            password.charAt(17) == '4' &&
            password.charAt(1) == '3' &&
            password.charAt(7) == 'b' &&
            password.charAt(10) == '_' &&
            password.charAt(5) == '4' &&
            password.charAt(9) == '3' &&
            password.charAt(11) == 't' &&
            password.charAt(15) == 'c' &&
            password.charAt(8) == 'l' &&
            password.charAt(12) == 'H' &&
            password.charAt(20) == 'c' &&
            password.charAt(14) == '_' &&
            password.charAt(6) == 'm' &&
            password.charAt(24) == '5' &&
            password.charAt(18) == 'r' &&
            password.charAt(13) == '3' &&
            password.charAt(19) == '4' &&
            password.charAt(21) == 'T' &&
            password.charAt(16) == 'H' &&
            password.charAt(27) == '3' &&
            password.charAt(30) == '4' &&
            password.charAt(25) == '_' &&
            password.charAt(22) == '3' &&
            password.charAt(28) == 'f' &&
            password.charAt(26) == '0' &&
            password.charAt(31) == '1';
    }
}

```

Write the following script to reconstruct the flag:

```python3
#!/usr/bin/env python3

# Input file should be VaultDoor1.java

import sys, re

if len(sys.argv) != 2:
    print("Please specify input file", file=sys.stderr)
    sys.exit(1)

f = open(sys.argv[1], 'r')

lines = filter(lambda l: "password.charAt" in l, f.readlines())

d = {}

for line in lines:
    i, c = re.findall(r"password\.charAt\((\d+)\)\s*==\s*'(\w)'", line)[0]
    d[int(i)] = c

flag = "".join([d[i] for i in range(max(d) + 1)])

print(flag)

f.close()

```

### vault-door-3 (200 points)

This vault uses for-loops and byte arrays. The source code for this vault is here: `VaultDoor3.java`

FLAG: `picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_c08866}`

```java
import java.util.*;

class VaultDoor3 {
    public static void main(String args[]) {
        VaultDoor3 vaultDoor = new VaultDoor3();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(), userInput.length() - 1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // Our security monitoring team has noticed some intrusions on some of the
    // less secure doors. Dr. Evil has asked me specifically to build a stronger
    // vault door to protect his Doomsday plans. I just *know* this door will
    // keep all of those nosy agents out of our business. Mwa ha!
    //
    // -Minion #2671
    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        char[] buffer = new char[32];
        int i;
        for (i = 0; i < 8; i++) {
            buffer[i] = password.charAt(i);
        }
        for (; i < 16; i++) {
            buffer[i] = password.charAt(23 - i);
        }
        for (; i < 32; i += 2) {
            buffer[i] = password.charAt(46 - i);
        }
        for (i = 31; i >= 17; i -= 2) {
            buffer[i] = password.charAt(i);
        }
        String s = new String(buffer);
        return s.equals("jU5t_a_sna_3lpm16g84c_u_4_m0r846");
    }
}

```

Use the following Python script:

```python3
#!/usr/bin/env python3

s = "jU5t_a_sna_3lpm16g84c_u_4_m0r846"

d = {}

for i in range(8):
    d[i] = s[i]

for i in range(8, 16):
    j = 23 - i
    d[j] = s[i]

for i in range(16, 32, 2):
    j = 46 - i
    d[j] = s[i]

for i in range(31, 16, -2):
    d[i] = s[i]

flag = "".join([d[i] for i in range(max(d) + 1)])

print(flag)

```

### vault-door-4 (250 points)

This vault uses ASCII encoding for the password. The source code for this vault is here: `VaultDoor4.java`

FLAG: `picoCTF{jU5t_4_bUnCh_0f_bYt3s_b9e92f76ac}`

```java
import java.util.*;

class VaultDoor4 {
    public static void main(String args[]) {
        VaultDoor4 vaultDoor = new VaultDoor4();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // I made myself dizzy converting all of these numbers into different bases,
    // so I just *know* that this vault will be impenetrable. This will make Dr.
    // Evil like me better than all of the other minions--especially Minion
    // #5620--I just know it!
    //
    //  .:::.   .:::.
    // :::::::.:::::::
    // :::::::::::::::
    // ':::::::::::::'
    //   ':::::::::'
    //     ':::::'
    //       ':'
    // -Minion #7781
    public boolean checkPassword(String password) {
        byte[] passBytes = password.getBytes();
        byte[] myBytes = {
            106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
            0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
            0142, 0131, 0164, 063 , 0163, 0137, 0142, 071 ,
            'e' , '9' , '2' , 'f' , '7' , '6' , 'a' , 'c' ,
        };
        for (int i=0; i<32; i++) {
            if (passBytes[i] != myBytes[i]) {
                return false;
            }
        }
        return true;
    }
}

```

Use the following Ruby script:

```ruby
#!/usr/bin/env ruby

cs = [106,85,53,116,95,52,95,98,0x55,0x6e,0x43,0x68,0x5f,0x30,0x66,0x5f,0142,0131,0164,063,0163,0137,0142,071,'e','9','2','f','7','6','a','c']
flag = cs.map{|c| c.chr}.join('')
puts flag

```

### asm1 (200 points)

What does `asm1(0x610)` return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. Source located in the directory at `/problems/asm1_1_95494d904d73b330976420bc1cd763ec`.

FLAG: `0x621`

```asm
asm1:
    <+0>:    push   ebp
    <+1>:    mov    ebp,esp
    <+3>:    cmp    DWORD PTR [ebp+0x8],0x3b9
    <+10>:   jg     0x50f <asm1+34>
    <+12>:   cmp    DWORD PTR [ebp+0x8],0x1
    <+16>:   jne    0x507 <asm1+26>
    <+18>:   mov    eax,DWORD PTR [ebp+0x8]
    <+21>:   add    eax,0x11
    <+24>:   jmp    0x526 <asm1+57>
    <+26>:   mov    eax,DWORD PTR [ebp+0x8]
    <+29>:   sub    eax,0x11
    <+32>:   jmp    0x526 <asm1+57>
    <+34>:   cmp    DWORD PTR [ebp+0x8],0x477
    <+41>:   jne    0x520 <asm1+51>
    <+43>:   mov    eax,DWORD PTR [ebp+0x8]
    <+46>:   sub    eax,0x11
    <+49>:   jmp    0x526 <asm1+57>
    <+51>:   mov    eax,DWORD PTR [ebp+0x8]
    <+54>:   add    eax,0x11
    <+57>:   pop    ebp
    <+58>:   ret
```

Just follow the step of the assembly code.

### asm2 (250 points)

What does `asm2(0x7,0x18)` return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. Source located in the directory at `/problems/asm2_3_edb10ce41667cb1cd4213657dae580fd`.

FLAG: `0x60`

```asm
asm2:
    <+0>:   push   ebp
    <+1>:   mov    ebp,esp
    <+3>:   sub    esp,0x10
    <+6>:   mov    eax,DWORD PTR [ebp+0xc]
    <+9>:   mov    DWORD PTR [ebp-0x4],eax
    <+12>:  mov    eax,DWORD PTR [ebp+0x8]
    <+15>:  mov    DWORD PTR [ebp-0x8],eax
    <+18>:  jmp    0x50c <asm2+31>
    <+20>:  add    DWORD PTR [ebp-0x4],0x1
    <+24>:  add    DWORD PTR [ebp-0x8],0xcc
    <+31>:  cmp    DWORD PTR [ebp-0x8],0x3937
    <+38>:  jle    0x501 <asm2+20>
    <+40>:  mov    eax,DWORD PTR [ebp-0x4]
    <+43>:  leave
    <+44>:  ret
```

As you can see, there is a loop at `asm2+38`. Hence, write the following Python script to calculate the value of [ebp-0x4] when the program exits from the loop:

```python3
a = 0x18
b = 0x7
while b <= 0x3937:
    a += 0x1
    b += 0xcc
print(hex(a))

# => 0x60
```

### asm3 (300 points)

What does `asm3(0xc4bd37e3,0xf516e15e,0xeea4f333)` return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. Source located in the directory at `/problems/asm3_4_c89016e12b8f3cac92a2e637c03f6139`.

FLAG: `0xe52c`

```asm
asm3:
   <+0>:    push   ebp
   <+1>:    mov    ebp,esp
   <+3>:    xor    eax,eax
   <+5>:    mov    ah,BYTE PTR [ebp+0x9]
   <+8>:    shl    ax,0x10
   <+12>:   sub    al,BYTE PTR [ebp+0xd]
   <+15>:   add    ah,BYTE PTR [ebp+0xe]
   <+18>:   xor    ax,WORD PTR [ebp+0x10]
   <+22>:   nop
   <+23>:   pop    ebp
   <+24>:   ret
```

Just follow the steps specified in assembly. Or we can just run the program and print out the result.

```asm
.intel_syntax noprefix
.global asm3

asm3:
        push   ebp
        mov    ebp,esp
        xor    eax,eax
        mov    ah,BYTE PTR [ebp+0x9]
        shl    ax,0x10
        sub    al,BYTE PTR [ebp+0xd]
        add    ah,BYTE PTR [ebp+0xe]
        xor    ax,WORD PTR [ebp+0x10]
        nop
        pop    ebp
        ret
```

```c
#include <stdio.h>

int asm3(int, int, int);

int main(int argc, char* argv[])
{
    printf("0x%x\n", asm3(0xc4bd37e3, 0xf516e15e, 0xeea4f333));
    return 0;
}
```

```bash
#!/bin/bash

gcc -masm=intel -m32 test.S -c -o test.o
gcc -m32 main.c -c -o main.o
gcc -m32 test.o main.o -o main
./main

# => 0xe52c
```

### reverse_cipher (300 points)

We have recovered a binary and a text file. Can you reverse the flag. Its also found in `/problems/reverse-cipher_5_6e21330f568439d366f5c038e32e5572` on the shell server.

FLAG: `picoCTF{r3v3rs3321bda1b}`

Given the binary file, we can use Ghidra to decompile it. Then, we can get the following decompiled `main` function in C.

```c

void main(void)

{
  size_t sVar1;
  char local_58 [23];
  char local_41;
  int local_2c;
  FILE *local_28;
  FILE *local_20;
  uint local_14;
  int local_10;
  char local_9;
  
  local_20 = fopen("flag.txt","r");
  local_28 = fopen("rev_this","a");
  if (local_20 == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (local_28 == (FILE *)0x0) {
    puts("please run this on the server");
  }
  sVar1 = fread(local_58,0x18,1,local_20);
  local_2c = (int)sVar1;
  if ((int)sVar1 < 1) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  local_10 = 0;
  while (local_10 < 8) {
    local_9 = local_58[local_10];
    fputc((int)local_9,local_28);
    local_10 = local_10 + 1;
  }
  local_14 = 8;
  while ((int)local_14 < 0x17) {
    if ((local_14 & 1) == 0) {
      local_9 = local_58[(int)local_14] + '\x05';
    }
    else {
      local_9 = local_58[(int)local_14] + -2;
    }
    fputc((int)local_9,local_28);
    local_14 = local_14 + 1;
  }
  local_9 = local_41;
  fputc((int)local_41,local_28);
  fclose(local_28);
  fclose(local_20);
  return;
}
```

Reading this function, we know the binary file basically take the original flag file and make some modification to it. Hence, we can write the following Python script to reverse the change and find the original flag:

```python3
#!/usr/bin/env python3

f = open("rev_this", "r")

flag = ""
modified_flag = f.readline().strip()

# Keep the first 8 chars to be the same

flag += modified_flag[:8]

# For index from 8 to 22, change the value back to the original

for i in range(8, 23):
    if i % 2 == 0:
    ¦   flag += chr(ord(modified_flag[i]) - 0x5)
    else:
    ¦   flag += chr(ord(modified_flag[i]) + 2)

# Add the last char

flag += modified_flag[-1]

f.close()

print(flag)
```

### droids0 (300 points)

Where do droid logs go. Check out this file. You can also find the file in `/problems/droids0_0_205f7b4a3b23490adffddfcfc45a2ca3`.

FLAG: `picoCTF{a.moose.once.bit.my.sister}`

Use Android Studio to open the `zero.apk` file (profile and debug) and run the application. In logcat, we can find the following record:

```text
2020-04-19 15:48:08.220 4856-4856/com.hellocmu.picoctf I/PICO: picoCTF{a.moose.once.bit.my.sister}
```

### vault-door-5 (300 points)

In the last challenge, you mastered octal (base 8), decimal (base 10), and hexadecimal (base 16) numbers, but this vault door uses a different change of base as well as URL encoding! The source code for this vault is here: `VaultDoor5.java`

FLAG: `picoCTF{c0nv3rt1ng_fr0m_ba5e_64_da882d01}`

```java
import java.net.URLDecoder;
import java.util.*;

class VaultDoor5 {
    public static void main(String args[]) {
        VaultDoor5 vaultDoor = new VaultDoor5();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(), userInput.length() - 1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // Minion #7781 used base 8 and base 16, but this is base 64, which is
    // like... eight times stronger, right? Riiigghtt? Well that's what my twin
    // brother Minion #2415 says, anyway.
    //
    // -Minion #2414
    public String base64Encode(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    // URL encoding is meant for web pages, so any double agent spies who steal
    // our source code will think this is a web site or something, defintely not
    // vault door! Oh wait, should I have not said that in a source code
    // comment?
    //
    // -Minion #2415
    public String urlEncode(byte[] input) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < input.length; i++) {
            buf.append(String.format("%%%2x", input[i]));
        }
        return buf.toString();
    }

    public boolean checkPassword(String password) {
        String urlEncoded = urlEncode(password.getBytes());
        String base64Encoded = base64Encode(urlEncoded.getBytes());
        String expected = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm" +
            "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2" +
            "JTM0JTVmJTY0JTYxJTM4JTM4JTMyJTY0JTMwJTMx";
        return base64Encoded.equals(expected);
    }
}
```

Reverse the whole procedure using the following Python script:

```python3
#!/usr/bin/env python3

import base64

s = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY0JTYxJTM4JTM4JTMyJTY0JTMwJTMx"
urlEncoded = base64.b64decode(s)
urlEncoded_list = [urlEncoded[i:i+3] for i in range(0, len(urlEncoded), 3)]
byte_list = [int(sym[1:], 16) for sym in urlEncoded_list]
char_list = [chr(b) for b in byte_list]
flag = "".join(char_list)
print(flag)
```

### vault-door-6 (350 points)

This vault uses an XOR encryption scheme. The source code for this vault is here: VaultDoor6.java

FLAG: `picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_0c3a2de}`

```java
import java.util.*;

class VaultDoor6 {
    public static void main(String args[]) {
        VaultDoor6 vaultDoor = new VaultDoor6();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // Dr. Evil gave me a book called Applied Cryptography by Bruce Schneier,
    // and I learned this really cool encryption system. This will be the
    // strongest vault door in Dr. Evil's entire evil volcano compound for sure!
    // Well, I didn't exactly read the *whole* book, but I'm sure there's
    // nothing important in the last 750 pages.
    //
    // -Minion #3091
    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        byte[] passBytes = password.getBytes();
        byte[] myBytes = {
            0x3b, 0x65, 0x21, 0xa , 0x38, 0x0 , 0x36, 0x1d,
            0xa , 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0xa ,
            0x21, 0x1d, 0x61, 0x3b, 0xa , 0x2d, 0x65, 0x27,
            0xa , 0x65, 0x36, 0x66, 0x34, 0x67, 0x31, 0x30,
        };
        for (int i=0; i<32; i++) {
            if (((passBytes[i] ^ 0x55) - myBytes[i]) != 0) {
                return false;
            }
        }
        return true;
    }
}
```

Use the following Python script to convert the bytes back to the original ones:

```python3
#!/usr/bin/env python3

bs = [0x3b,0x65,0x21,0xa,0x38,0x0,0x36,0x1d,0xa,0x3d,0x61,0x27,0x11,0x66,0x27,0xa,0x21,0x1d,0x61,0x3b,0xa,0x2d,0x65,0x27,0xa,0x65,0x36,0x66,0x34,0x67,0x31,0x30]

flag = "".join([chr(b ^ 0x55) for b in bs])
print(flag)
```

### Need For Speed (400 points)

The name of the game is speed. Are you quick enough to solve this problem and keep it above 50 mph? `need-for-speed`.

FLAG: `PICOCTF{Good job keeping bus #1cf20c02 speeding along!}`

```bash
deepzero@ubuntu:~/Desktop$ cp need-for-speed patched
deepzero@ubuntu:~/Desktop$ ls
need-for-speed  patched  patched.log
deepzero@ubuntu:~/Desktop$ r2 patched
[0x000006b0]> aaa
[Invalid instruction of 16367 bytes at 0x1cb entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000006b0]> afl
0x00000000    6 459  -> 485  sym.imp.__libc_start_main
0x00000610    3 23           sym._init
0x00000640    1 6            sym.imp.putchar
0x00000650    1 6            sym.imp.puts
0x00000660    1 6            sym.imp.printf
0x00000670    1 6            sym.imp.alarm
0x00000680    1 6            sym.imp.__sysv_signal
0x00000690    1 6            sym.imp.exit
0x000006a0    1 6            sub.__cxa_finalize_6a0
0x000006b0    1 43           entry0
0x000006e0    4 50   -> 40   sym.deregister_tm_clones
0x00000720    4 66   -> 57   sym.register_tm_clones
0x00000770    5 58   -> 51   sym.__do_global_dtors_aux
0x000007b0    1 10           entry.init0
0x000007ba    6 135          sym.decrypt_flag
0x00000841    3 29           sym.calculate_key
0x0000085e    1 33           sym.alarm_handler
0x0000087f    3 88           sym.set_timer
0x000008d7    1 47           sym.get_key
0x00000906    1 44           sym.print_flag
0x00000932    4 66           sym.header
0x00000974    1 62           sym.main
0x000009c0    3 101  -> 92   sym.__libc_csu_init
0x00000a30    1 2            sym.__libc_csu_fini
0x00000a34    1 9            sym._fini
[0x000006b0]> s sym.get_key
[0x000008d7]> pdf
/ (fcn) sym.get_key 47
|   sym.get_key ();
|           ; CALL XREF from sym.main (0x99c)
|           0x000008d7      55             push rbp
|           0x000008d8      4889e5         mov rbp, rsp
|           0x000008db      488d3dfc0100.  lea rdi, qword str.Creating_key... ; 0xade ; "Creating key..." ; const char *s
|           0x000008e2      e869fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x000008e7      b800000000     mov eax, 0
|           0x000008ec      e850ffffff     call sym.calculate_key
|           0x000008f1      890565072000   mov dword [obj.key], eax    ; [0x20105c:4]=0
|           0x000008f7      488d3df00100.  lea rdi, qword str.Finished ; 0xaee ; "Finished" ; const char *s
|           0x000008fe      e84dfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00000903      90             nop
|           0x00000904      5d             pop rbp
\           0x00000905      c3             ret
[0x000008d7]> s sym.calculate_key
[0x00000841]> pdf
/ (fcn) sym.calculate_key 29
|   sym.calculate_key ();
|           ; var unsigned int local_4h @ rbp-0x4
|           ; CALL XREF from sym.get_key (0x8ec)
|           0x00000841      55             push rbp
|           0x00000842      4889e5         mov rbp, rsp
|           0x00000845      c745fc566147.  mov dword [local_4h], 0xd2476156
|           ; CODE XREF from sym.calculate_key (0x857)
|       .-> 0x0000084c      836dfc01       sub dword [local_4h], 1
|       :   0x00000850      817dfcabb023.  cmp dword [local_4h], 0xe923b0ab
|       `=< 0x00000857      75f3           jne 0x84c
|           0x00000859      8b45fc         mov eax, dword [local_4h]
|           0x0000085c      5d             pop rbp
\           0x0000085d      c3             ret
[0x00000841]> oo+
[0x00000841]> s 0x00000845
[0x00000845]> pd
|           0x00000845      c745fc566147.  mov dword [local_4h], 0xd2476156
|           ; CODE XREF from sym.calculate_key (0x857)
|       .-> 0x0000084c      836dfc01       sub dword [local_4h], 1
|       :   0x00000850      817dfcabb023.  cmp dword [local_4h], 0xe923b0ab
|       `=< 0x00000857      75f3           jne 0x84c
|           0x00000859      8b45fc         mov eax, dword [local_4h]
|           0x0000085c      5d             pop rbp
\           0x0000085d      c3             ret
/ (fcn) sym.alarm_handler 33
|   sym.alarm_handler (int arg1);
|           ; var int local_4h @ rbp-0x4
|           ; arg int arg1 @ rdi
|           ; DATA XREF from sym.set_timer (0x88e)
|           0x0000085e      55             push rbp
|           0x0000085f      4889e5         mov rbp, rsp
|           0x00000862      4883ec10       sub rsp, 0x10
|           0x00000866      897dfc         mov dword [local_4h], edi   ; arg1
|           0x00000869      488d3de00100.  lea rdi, qword str.Not_fast_enough._BOOM ; 0xa50 ; "Not fast enough. BOOM!" ; const char *s
|           0x00000870      e8dbfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00000875      bf00000000     mov edi, 0                  ; int status
\           0x0000087a      e811feffff     call sym.imp.exit           ; void exit(int status)
/ (fcn) sym.set_timer 88
|   sym.set_timer ();
|           ; var int local_ch @ rbp-0xc
|           ; var unsigned int local_8h @ rbp-0x8
|           ; CALL XREF from sym.main (0x992)
|           0x0000087f      55             push rbp
|           0x00000880      4889e5         mov rbp, rsp
|           0x00000883      4883ec10       sub rsp, 0x10
|           0x00000887      c745f4010000.  mov dword [local_ch], 1
|           0x0000088e      488d35c9ffff.  lea rsi, qword [sym.alarm_handler] ; 0x85e
|           0x00000895      bf0e000000     mov edi, 0xe
|           0x0000089a      e8e1fdffff     call sym.imp.__sysv_signal
|           0x0000089f      488945f8       mov qword [local_8h], rax
|           0x000008a3      48837df8ff     cmp qword [local_8h], -1
|       ,=< 0x000008a8      7520           jne 0x8ca
|       |   0x000008aa      be3c000000     mov esi, 0x3c               ; '<'
|       |   0x000008af      488d3db20100.  lea rdi, qword str.Something_bad_happened_here.___If_running_on_the_shell_server__Please_contact_the_admins_with__need_for_speed.c:_d_. ; 0xa68 ; "\n\nSomething bad happened here. \nIf running on the shell server\nPlease contact the admins with \"need-for-speed.c:%d\".\n" ; const char *format
|       |   0x000008b6      b800000000     mov eax, 0
|       |   0x000008bb      e8a0fdffff     call sym.imp.printf         ; int printf(const char *format)
|       |   0x000008c0      bf00000000     mov edi, 0                  ; int status
|       |   0x000008c5      e8c6fdffff     call sym.imp.exit           ; void exit(int status)
|       |   ; CODE XREF from sym.set_timer (0x8a8)
|       `-> 0x000008ca      8b45f4         mov eax, dword [local_ch]
|           0x000008cd      89c7           mov edi, eax
|           0x000008cf      e89cfdffff     call sym.imp.alarm
|           0x000008d4      90             nop
|           0x000008d5      c9             leave
\           0x000008d6      c3             ret
/ (fcn) sym.get_key 47
|   sym.get_key ();
|           ; CALL XREF from sym.main (0x99c)
|           0x000008d7      55             push rbp
|           0x000008d8      4889e5         mov rbp, rsp
|           0x000008db      488d3dfc0100.  lea rdi, qword str.Creating_key... ; 0xade ; "Creating key..." ; const char *s
|           0x000008e2      e869fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x000008e7      b800000000     mov eax, 0
|           0x000008ec      e850ffffff     call sym.calculate_key
|           0x000008f1      890565072000   mov dword [obj.key], eax    ; [0x20105c:4]=0
|           0x000008f7      488d3df00100.  lea rdi, qword str.Finished ; 0xaee ; "Finished" ; const char *s
|           0x000008fe      e84dfdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00000903      90             nop
|           0x00000904      5d             pop rbp
\           0x00000905      c3             ret
/ (fcn) sym.print_flag 44
|   sym.print_flag ();
|           ; CALL XREF from sym.main (0x9a6)
|           0x00000906      55             push rbp
|           0x00000907      4889e5         mov rbp, rsp
|           0x0000090a      488d3de60100.  lea rdi, qword str.Printing_flag: ; 0xaf7 ; "Printing flag:" ; const char *s
|           0x00000911      e83afdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00000916      8b0540072000   mov eax, dword [obj.key]    ; [0x20105c:4]=0
|           0x0000091c      89c7           mov edi, eax
|           0x0000091e      e897feffff     call sym.decrypt_flag
|           0x00000923      488d3df60620.  lea rdi, qword obj.flag     ; 0x201020 ; const char *s
|           0x0000092a      e821fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0000092f      90             nop
|           0x00000930      5d             pop rbp
\           0x00000931      c3             ret
/ (fcn) sym.header 66
|   sym.header ();
|           ; var int local_4h @ rbp-0x4
|           ; CALL XREF from sym.main (0x988)
|           0x00000932      55             push rbp
|           0x00000933      4889e5         mov rbp, rsp
|           0x00000936      4883ec10       sub rsp, 0x10
[0x00000845]> pd 1
|           0x00000845      c745fc566147.  mov dword [local_4h], 0xd2476156
[0x00000845]> wa mov dword [rbp-0x4], 0xe923b0ac
Written 7 byte(s) (mov dword [rbp-0x4], 0xe923b0ac) = wx c745fcacb023e9
[0x00000845]> q
deepzero@ubuntu:~/Desktop$ chmod u+x patched
deepzero@ubuntu:~/Desktop$ ./patched 
Keep this thing over 50 mph!
============================

Creating key...
Finished
Printing flag:
PICOCTF{Good job keeping bus #1cf20c02 speeding along!}
```

### Time's Up (400 points)

Time waits for no one. Can you solve this before time runs out? times-up, located in the directory at `/problems/time-s-up_4_548d4bc5ce82bf27864a00001fcbd182`.

FLAG: `picoCTF{Gotta go fast. Gotta go FAST. #046cc375}`

If we directly run the program, we will see the following:

```bash
deepzero@ubuntu:~/Desktop$ ./times-up
Challenge: (((((-854810748) + (-941288844)) + ((-1286900858) - (-998483204))) + (((-758743650) - (-1455902769)) + ((-43638189) - (-2048651958)))) + ((((-1626304089) + (1930199724)) - ((-1542888128) + (-473499864))) - (((-1596619552) + (-531550730)) + ((-722586188) + (-747081157)))))
Setting alarm...
Solution? Alarm clock
```

As you can see, the program generates an equation and expects you to input the answer in a blink of eye...

Let's figure out how long we have to input the answer before it times out using `strace`.

```bash
deepzero@ubuntu:~/Desktop$ strace ./times-up 
execve("./times-up", ["./times-up"], 0x7ffd755e9ce0 /* 51 vars */) = 0
brk(NULL)                               = 0x55b155d02000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffe363051b0) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=71772, ...}) = 0
mmap(NULL, 71772, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f3033a3f000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\360r\2\0\0\0\0\0"..., 832) = 832
lseek(3, 64, SEEK_SET)                  = 64
read(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784) = 784
lseek(3, 848, SEEK_SET)                 = 848
read(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32) = 32
lseek(3, 880, SEEK_SET)                 = 880
read(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0q7?\324>\326\250>\n\253\230<:\227\0362"..., 68) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2025032, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3033a3d000
lseek(3, 64, SEEK_SET)                  = 64
read(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784) = 784
lseek(3, 848, SEEK_SET)                 = 848
read(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32) = 32
lseek(3, 880, SEEK_SET)                 = 880
read(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0q7?\324>\326\250>\n\253\230<:\227\0362"..., 68) = 68
mmap(NULL, 2032984, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f303384c000
mmap(0x7f3033871000, 1540096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7f3033871000
mmap(0x7f30339e9000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19d000) = 0x7f30339e9000
mmap(0x7f3033a33000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e6000) = 0x7f3033a33000
mmap(0x7f3033a39000, 13656, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f3033a39000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7f3033a3e540) = 0
mprotect(0x7f3033a33000, 12288, PROT_READ) = 0
mprotect(0x55b15484d000, 4096, PROT_READ) = 0
mprotect(0x7f3033a7d000, 4096, PROT_READ) = 0
munmap(0x7f3033a3f000, 71772)           = 0
rt_sigaction(SIGALRM, {sa_handler=SIG_DFL, sa_mask=[ALRM], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f3033892470}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
brk(NULL)                               = 0x55b155d02000
brk(0x55b155d23000)                     = 0x55b155d23000
write(1, "Challenge: (((((-504915624) - (1"..., 281Challenge: (((((-504915624) - (1894965760)) - ((-1970550000) + (-1375473640))) + (((1134240392) + (1854332308)) + ((1788050992) + (1614043556)))) + ((((1885270848) - (970931223)) + ((-1798664131) + (-1254097730))) + (((541877902) + (-1171023374)) + ((75858856) + (-1204645376)))))
) = 281
write(1, "Setting alarm...\n", 17Setting alarm...
)      = 17
setitimer(ITIMER_REAL, {it_interval={tv_sec=0, tv_usec=0}, it_value={tv_sec=0, tv_usec=5000}}, {it_interval={tv_sec=0, tv_usec=0}, it_value={tv_sec=0, tv_usec=0}}) = 0
fstat(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "Solution? ", 10Solution? )              = 10
read(0, 0x55b155d026b0, 1024)           = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
--- SIGALRM {si_signo=SIGALRM, si_code=SI_KERNEL} ---
+++ killed by SIGALRM +++
Alarm clock
```

At near the end of the output, we see `it_value={tv_sec=0, tv_usec=5000}`. Hence, the time for us to input the answer is 5000 us.

Write the following bash script to calculate the answer and input it into the program:

```bash
#!/bin/bash

coproc ./times-up
read LINE <&${COPROC[0]}
echo $(echo ${LINE:11} | bc) >&${COPROC[1]}
cat <&${COPROC[0]}
```

Then, we will get the following result:

```bash
deepzero:~$ ls
test.sh
deepzero:~$ cd /problems/time-s-up_4_548d4bc5ce82bf27864a00001fcbd182
deepzero:/problems/time-s-up_4_548d4bc5ce82bf27864a00001fcbd182$ bash ~/test.sh 
Setting alarm...
picoCTF{Gotta go fast. Gotta go FAST. #046cc375}
Solution? Congrats! Here is the flag!
deepzero:/problems/time-s-up_4_548d4bc5ce82bf27864a00001fcbd182$
```

### droids1 (350 points)

Find the pass, get the flag. Check out this file. You can also find the file in `/problems/droids1_0_b7f94e21c7e45e6604972f9bc3f50e24`.

FLAG: `picoCTF{pining.for.the.fjords}`

Follow the same procedures as we have done in `droid0`. This time, we have to type in a password into the app to show the flag.

Use the following Bash command to find the password:

```bash
$ find . -type f | xargs cat | grep password
    <public type="string" name="password" id="0x7f0b002f" />
    <string name="password">opossum</string>
    .param p1, "password"    # Z
    const-string v2, "; password: "
    .local v0, "password":Ljava/lang/String;
.field public static final password:I = 0x7f0b002f
```

Hence, we know that the password is `opossum`. Fill that in and we can see the flag is `picoCTF{pining.for.the.fjords}`.

### asm4 (400 points)

What will `asm4("picoCTF_376ee")` return? Submit the flag as a hexadecimal value (starting with `'0x'`). NOTE: Your submission for this question will NOT be in the normal flag format. Source located in the directory at `/problems/asm4_2_0932017a5f5efe2bc813afd0fe0603aa`.

FLAG: ``



Follow the same procedure as we did in `asm3` and create the following `main.c` file:

```c
#include <stdio.h>

int asm4(char *);

int main()
{
    printf("0x%x\n", asm4("picoCTF_376ee"));
    return 0;
}
```

Also, modify `asm4.S` to be the following:

```asm
.intel_syntax noprefix
.global asm4

asm4:
    push   ebp
    mov    ebp,esp
    push   ebx
    sub    esp,0x10
    mov    DWORD PTR [ebp-0x10],0x25c
    mov    DWORD PTR [ebp-0xc],0x0
    jmp    _asm4_27
_asm4_23:
    add    DWORD PTR [ebp-0xc],0x1
_asm4_27:
    mov    edx,DWORD PTR [ebp-0xc]
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,edx
    movzx  eax,BYTE PTR [eax]
    test   al,al
    jne    _asm4_23
    mov    DWORD PTR [ebp-0x8],0x1
    jmp    _asm4_138
_asm4_51:
    mov    edx,DWORD PTR [ebp-0x8]
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,edx
    movzx  eax,BYTE PTR [eax]
    movsx  edx,al
    mov    eax,DWORD PTR [ebp-0x8]
    lea    ecx,[eax-0x1]
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,ecx
    movzx  eax,BYTE PTR [eax]
    movsx  eax,al
    sub    edx,eax
    mov    eax,edx
    mov    edx,eax
    mov    eax,DWORD PTR [ebp-0x10]
    lea    ebx,[edx+eax*1]
    mov    eax,DWORD PTR [ebp-0x8]
    lea    edx,[eax+0x1]
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,edx
    movzx  eax,BYTE PTR [eax]
    movsx  edx,al
    mov    ecx,DWORD PTR [ebp-0x8]
    mov    eax,DWORD PTR [ebp+0x8]
    add    eax,ecx
    movzx  eax,BYTE PTR [eax]
    movsx  eax,al
    sub    edx,eax
    mov    eax,edx
    add    eax,ebx
    mov    DWORD PTR [ebp-0x10],eax
    add    DWORD PTR [ebp-0x8],0x1
_asm4_138:
    mov    eax,DWORD PTR [ebp-0xc]
    sub    eax,0x1
    cmp    DWORD PTR [ebp-0x8],eax
    jl     _asm4_51
    mov    eax,DWORD PTR [ebp-0x10]
    add    esp,0x10
    pop    ebx
    pop    ebp
    ret
```

Create the following Bash script to run the program:

```bash
#!/bin/bash

gcc -masm=intel -m32 asm4.S -c -o asm4.o
gcc -m32 main.c -c -o main.o
gcc -m32 asm4.o main.o -o main
./main
# => 0x24d
```

### droids2 (400 points)

Find the pass, get the flag. Check out this file. You can also find the file in `/problems/droids2_0_bf474794b5a228db3498ba3198db54d7`.

FLAG: `picoCTF{what.is.your.favourite.colour}`

Unlike the previous droids, we cannot directly find the password. We can use `jadx` to decompile the application. Inside `/Users/mikoto/Desktop/picoCTF-2019-Sol/ReverseEngineering/droid2/two/sources/com/hellocmu/picoctf`, we can find `FlagstaffHill.java`:

```java
package com.hellocmu.picoctf;

import android.content.Context;

public class FlagstaffHill {
    public static native String sesame(String str);

    public static String getFlag(String input, Context ctx) {
        String[] witches = {"weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"};
        int second = 3 - 3;
        int third = (3 / 3) + second;
        int fourth = (third + third) - second;
        int fifth = 3 + fourth;
        if (input.equals("".concat(witches[fifth]).concat(".").concat(witches[third]).concat(".").concat(witches[second]).concat(".").concat(witches[(fifth + second) - third]).concat(".").concat(witches[3]).concat(".").concat(witches[fourth]))) {
            return sesame(input);
        }
        return "NOPE";
    }
}
```

Following the code, we know that the password is `dismass.ogg.weatherwax.aching.nitt.garlick`.

If we input the password, we can see the flag is `picoCTF{what.is.your.favourite.colour}`.

### vault-door-7 (400 points)

This vault uses bit shifts to convert a password string into an array of integers. Hurry, agent, we are running out of time to stop Dr. Evil's nefarious plans! The source code for this vault is here: `VaultDoor7.java`

FLAG: `picoCTF{A_b1t_0f_b1t_sh1fTiNg_d79dd25ce3}`

```java
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

class VaultDoor7 {
    public static void main(String args[]) {
        VaultDoor7 vaultDoor = new VaultDoor7();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(), userInput.length() - 1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // Each character can be represented as a byte value using its
    // ASCII encoding. Each byte contains 8 bits, and an int contains
    // 32 bits, so we can "pack" 4 bytes into a single int. Here's an
    // example: if the hex string is "01ab", then those can be
    // represented as the bytes {0x30, 0x31, 0x61, 0x62}. When those
    // bytes are represented as binary, they are:
    //
    // 0x30: 00110000
    // 0x31: 00110001
    // 0x61: 01100001
    // 0x62: 01100010
    //
    // If we put those 4 binary numbers end to end, we end up with 32
    // bits that can be interpreted as an int.
    //
    // 00110000001100010110000101100010 -> 808542562
    //
    // Since 4 chars can be represented as 1 int, the 32 character password can
    // be represented as an array of 8 ints.
    //
    // - Minion #7816
    public int[] passwordToIntArray(String hex) {
        int[] x = new int[8];
        byte[] hexBytes = hex.getBytes();
        for (int i = 0; i < 8; i++) {
            x[i] = hexBytes[i * 4] << 24 |
                hexBytes[i * 4 + 1] << 16 |
                hexBytes[i * 4 + 2] << 8 |
                hexBytes[i * 4 + 3];
        }
        return x;
    }

    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        int[] x = passwordToIntArray(password);
        return x[0] == 1096770097 &&
            x[1] == 1952395366 &&
            x[2] == 1600270708 &&
            x[3] == 1601398833 &&
            x[4] == 1716808014 &&
            x[5] == 1734304823 &&
            x[6] == 962880562 &&
            x[7] == 895706419;
    }
}
```

We can write the following Python script to reverse the procedure and reconstruct the flag:

```python3
#!/usr/bin/env python3

xs = [1096770097, 1952395366, 1600270708, 1601398833, 1716808014, 1734304823, 962880562, 895706419]
flag = ""
for x  in xs:
    ss = [8 * i for i in reversed(range(4))]
    ms = [0xFF << s for s in ss]
    vs = [(ms[i] & x) >> ss[i] for i in range(len(ss))]
    us = [chr(int(hex(v), 16)) for v in vs]
    flag += "".join(us)
print(flag)

# => A_b1t_0f_b1t_sh1fTiNg_d79dd25ce3
```

### Time's Up, Again! (450 points)

Previously you solved things fast. Now you've got to go faster. Much faster. Can you solve *this one* before time runs out? times-up-again, located in the directory at `/problems/time-s-up--again-_3_f7219b295d1ce306013aea2d0ab82c27`.

FLAG: `picoCTF{Hasten. Hurry. Ferrociously Speedy. #1dc758f2}`

Following the same idea as the previous `times-up` problem, we can use `strace` to see the how long the timer would alarm before we input the answer.

```text
deepzero@localhost:~/picoCTF$ strace ./times-up-again 
execve("./times-up-again", ["./times-up-again"], [/* 17 vars */]) = 0
brk(0)                                  = 0x555555759000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff9000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=102896, ...}) = 0
mmap(NULL, 102896, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ffff7fdf000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\357\1\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1607696, ...}) = 0
mmap(NULL, 3721272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff7a50000
mprotect(0x7ffff7bd4000, 2093056, PROT_NONE) = 0
mmap(0x7ffff7dd3000, 20480, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x183000) = 0x7ffff7dd3000
mmap(0x7ffff7dd8000, 18488, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7dd8000
close(3)                                = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fde000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fdd000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fdc000
arch_prctl(ARCH_SET_FS, 0x7ffff7fdd700) = 0
mprotect(0x7ffff7dd3000, 16384, PROT_READ) = 0
mprotect(0x555555755000, 4096, PROT_READ) = 0
mprotect(0x7ffff7ffc000, 4096, PROT_READ) = 0
munmap(0x7ffff7fdf000, 102896)          = 0
rt_sigaction(SIGALRM, {SIG_DFL, [ALRM], SA_RESTORER|SA_RESTART, 0x7ffff7a821a0}, {SIG_DFL, [], 0}, 8) = 0
time(NULL)                              = 1587425845
brk(0)                                  = 0x555555759000
brk(0x55555577a000)                     = 0x55555577a000
open("/dev/urandom", O_RDONLY)          = 3
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 152), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff8000
fstat(3, {st_mode=S_IFCHR|0666, st_rdev=makedev(1, 9), ...}) = 0
ioctl(3, SNDCTL_TMR_TIMEBASE or TCGETS, 0x7fffffffe2b0) = -1 EINVAL (Invalid argument)
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff7000
read(3, "\204\340\223\365\3756A\177\337\262s'\26D\272\310\f\245\7\216\0057\274\\\232\231\373\315\t\372`\352"..., 4096) = 4096
write(1, "Challenge: (((((-174858108) + (6"..., 277Challenge: (((((-174858108) + (661893855)) - ((-1912101620) + (-839149158))) * (((-1981753746) * (465526088)) + ((751655980) - (1727566328)))) * ((((-209240140) - (753877555)) - ((-270236583) * (-1363945212))) - (((-1521559377) - (49330417)) + ((1278820237) * (-579390559)))))
) = 277
write(1, "Setting alarm...\n", 17Setting alarm...
)      = 17
setitimer(ITIMER_REAL, {it_interval={0, 0}, it_value={0, 200}}, {it_interval={0, 0}, it_value={0, 0}}) = 0
fstat(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 152), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff6000
write(1, "Solution? ", 10)              = ? ERESTARTSYS (To be restarted)
--- SIGALRM (Alarm clock) @ 0 (0) ---
+++ killed by SIGALRM +++
Alarm clock
```

As we can see, the program gives 200 us to solve the problem, which is much shorter than the previous time. Although there is way to write a C program to run the target program by reading from and writing to forked process through pipelines, it takes too much code. Hence, I choose to adopt a way that I have found online. That is, we can block the `ALARM` signal to slow down the target program.

```c
#include <signal.h>
#include <unistd.h>

int main(){
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGALRM);
    sigprocmask(SIG_BLOCK, &sigs, 0);

    execl("./times-up-again", "times-up-again", NULL);
}
```

We can compile the program with the following command:

```bash
deepzero@localhost $ gcc -Wall -g -std=c11 -D_POSIX_SOURCE main.c -o main
```

If we run the program, we would see the following:

```bash
deepzero@localhost:/problems/time-s-up--again-_3_f7219b295d1ce306013aea2d0ab82c27$ ~/main
Challenge: (((((591354935) + (189091348)) + ((-1699811656) - (1409154097))) - (((1836108634) + (1664254202)) + ((-1124524879) + (-1453163354)))) - ((((1836092023) + (1531548464)) - ((-303509607) - (-2077750124))) - ((((1980893543) + (1021617250)) + ((-473606947) + (792896657))) + ((-1214926167) - (-1482717717)))))
Setting alarm...
Solution?
```

Copy the expression to Python interpreter and get the answer.

```text
>>> (((((591354935) + (189091348)) + ((-1699811656) - (1409154097))) - (((1836108634) + (1664254202)) + ((-1124524879) + (-1453163354)))) - ((((1836092023) + (1531548464)) - ((-303509607) - (-2077750124))) - ((((1980893543) + (1021617250)) + ((-473606947) + (792896657))) + ((-1214926167) - (-1482717717)))))
-1255001990
```

Put the answer back to the console.

```bash
deepzero@localhost:/problems/time-s-up--again-_3_f7219b295d1ce306013aea2d0ab82c27$ ~/main
Challenge: (((((591354935) + (189091348)) + ((-1699811656) - (1409154097))) - (((1836108634) + (1664254202)) + ((-1124524879) + (-1453163354)))) - ((((1836092023) + (1531548464)) - ((-303509607) - (-2077750124))) - ((((1980893543) + (1021617250)) + ((-473606947) + (792896657))) + ((-1214926167) - (-1482717717)))))
Setting alarm...
Solution? -1255001990
Congrats! Here is the flag.txt!
picoCTF{Hasten. Hurry. Ferrociously Speedy. #1dc758f2}
```

One thing to notice is that the target program would reject the answer if the answer is too big. This may be related to how the program handles integers.

### droids3 (450 points)

Find the pass, get the flag. Check out this file. You can also find the file in `/problems/droids3_0_b475775d8018b2a030a38c40e3b0e25c`.

FLAG: `picoCTF{tis.but.a.scratch}`

First use `jadx` to decompile the `apk` file and read `three/sources/com/hellocmu/picoctf/FlagstaffHill.java`:

```java
package com.hellocmu.picoctf;

import android.content.Context;

public class FlagstaffHill {
    public static native String cilantro(String str);

    public static String nope(String input) {
        return "don't wanna";
    }

    public static String yep(String input) {
        return cilantro(input);
    }

    public static String getFlag(String input, Context ctx) {
        return nope(input);
    }
}
```

As you can see, `getFlag` would always return `nope(input)`. What we need to do is to change nope to `yep`. That means, we need to modify the file and recompile the files to `apk`.

Use `apktool` to dissemble `three.apk` and open `three/smali/com/hellocmu/picoctf/FlagstaffHill.smali`:

```text
.class public Lcom/hellocmu/picoctf/FlagstaffHill;
.super Ljava/lang/Object;
.source "FlagstaffHill.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static native cilantro(Ljava/lang/String;)Ljava/lang/String;
.end method

.method public static getFlag(Ljava/lang/String;Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .param p0, "input"    # Ljava/lang/String;
    .param p1, "ctx"    # Landroid/content/Context;

    .line 19
    invoke-static {p0}, Lcom/hellocmu/picoctf/FlagstaffHill;->nope(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 20
    .local v0, "flag":Ljava/lang/String;
    return-object v0
.end method

.method public static nope(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p0, "input"    # Ljava/lang/String;

    .line 11
    const-string v0, "don\'t wanna"

    return-object v0
.end method

.method public static yep(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p0, "input"    # Ljava/lang/String;

    .line 15
    invoke-static {p0}, Lcom/hellocmu/picoctf/FlagstaffHill;->cilantro(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
```

Change

```text
invoke-static {p0}, Lcom/hellocmu/picoctf/FlagstaffHill;->nope(Ljava/lang/String;)Ljava/lang/String;
```

to

```text
invoke-static {p0}, Lcom/hellocmu/picoctf/FlagstaffHill;->yep(Ljava/lang/String;)Ljava/lang/String;
```

Then, use `apktool` to make the files back to `three.apk` as follows:

```bash
deepzero@localhost $ apktool b three -o three.apk
```

Notice that we cannot directly install `three.apk`. If we do that, we will see error: `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.

We can use `uber-apk-signer.jar` to sign the `apk` file:

```bash
deepzero@localhost $ java -jar uber-apk-signer-1.1.0.jar -apk three.apk
```

Now, we can follow the same procedure and use Android Studio to open file and see the flag.
