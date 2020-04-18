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
