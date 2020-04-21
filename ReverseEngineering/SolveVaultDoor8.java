import java.util.*;

public class SolveVaultDoor8 {
    public static void main(String[] args) {
        char[] expected = {
            0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4,
            0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86,
            0xD0, 0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xE1,
            0xC0, 0xA4, 0x95, 0x94, 0xD1, 0x95, 0x94, 0xD0
        };
        String expected_str = String.valueOf(expected);
        char[] decrypted = unscramble(expected_str);
        System.out.println(String.valueOf(decrypted));
    }

    public static char[] unscramble(String input) {   
        char[] password = input.toCharArray();
        for (int i = 0; i < password.length; i++) {   
            char c = password[i];
            c = switchBits(c, 6, 7);
            c = switchBits(c, 2, 5);
            c = switchBits(c, 3, 4);
            c = switchBits(c, 0, 1);
            c = switchBits(c, 4, 7);
            c = switchBits(c, 5, 6);
            c = switchBits(c, 0, 3);
            c = switchBits(c, 1, 2);
            password[i] = c;
        }
        return password;
    } 

    public static char switchBits(char c, int p1, int p2) {
        char mask1  = (char)(1 << p1);
        char mask2  = (char)(1 << p2);
        char bit1   = (char)(c & mask1);
        char bit2   = (char)(c & mask2); 
        char rest   = (char)(c & ~(mask1 | mask2));
        char shift  = (char)(p2 - p1);
        char result = (char)((bit1 << shift) | (bit2 >> shift) | rest);
        return result;
    }
}
