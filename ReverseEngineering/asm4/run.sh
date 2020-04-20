#!/bin/bash

gcc -masm=intel -m32 asm4.S -c -o asm4.o
gcc -m32 main.c -c -o main.o
gcc -m32 asm4.o main.o -o main
./main
