# Cryptography

### The Numbers (50 points)

The numbers... what do they mean?

![the numbers](./the_numbers.png)

FLAG:`PICOCTF{THENUMBERSMASON}`

```text
16 9 3 15 3 20 6 { 20 8 5
14 21 13 2 5 18 19 13 1
19 15 14 }
```

We know that the numbers represent the flag. The numbers before `{` is `PICOCTF`. The distance from `C` to `O` is still 12, so `A->1`.

```python3
>>> "20 8 5 14 21 13 2 5 18 19 13 1 19 15 14".split()
>>> ''.join(map(lambda v: chr(v - 1 + ord('A')), map(int, _)))
# => 'THENUMBERSMASON'
```

Hence, the flag is `PICOCTF{THENUMBERSMASON}`

### 13 (100 points)

Cryptography can be easy, do you know what ROT13 is? `cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}`

FLAG: `picoCTF{not_too_bad_of_a_problem}`

*rot13.py*:

```python3
import sys

def rot13(s):
    def shift(c, forward=True):
        d = 13 if forward else -13

        if c >= 'a' and c <= 'z':
            return chr(((ord(c) - ord('a') + d) % 26) + ord('a'))

        if c >= 'A' and c <= 'Z':
            return chr(((ord(c) - ord('A') + d) % 26) + ord('A'))

        return c

    return ''.join(map(shift, s))


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <string>")
        sys.exit(1)

    print(rot13(sys.argv[1]))


if __name__ == '__main__':
    main()
```

```bash
$ python3 rot13.py "cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}"
# => picoCTF{not_too_bad_of_a_problem}
```

### Easy1 (100 points)

The one time pad can be cryptographically secure, but not when you know the key. Can you solve this? We've given you the encrypted flag, key, and a table to help UFJKXQZQUNB with the key of SOLVECRYPTO. Can you use this table to solve it?

FLAG: `picoCTF{CRYPTOISFUN}`

```text
    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
   +----------------------------------------------------
A | A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
B | B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
C | C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
D | D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
E | E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
F | F G H I J K L M N O P Q R S T U V W X Y Z A B C D E
G | G H I J K L M N O P Q R S T U V W X Y Z A B C D E F
H | H I J K L M N O P Q R S T U V W X Y Z A B C D E F G
I | I J K L M N O P Q R S T U V W X Y Z A B C D E F G H
J | J K L M N O P Q R S T U V W X Y Z A B C D E F G H I
K | K L M N O P Q R S T U V W X Y Z A B C D E F G H I J
L | L M N O P Q R S T U V W X Y Z A B C D E F G H I J K
M | M N O P Q R S T U V W X Y Z A B C D E F G H I J K L
N | N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
O | O P Q R S T U V W X Y Z A B C D E F G H I J K L M N
P | P Q R S T U V W X Y Z A B C D E F G H I J K L M N O
Q | Q R S T U V W X Y Z A B C D E F G H I J K L M N O P
R | R S T U V W X Y Z A B C D E F G H I J K L M N O P Q
S | S T U V W X Y Z A B C D E F G H I J K L M N O P Q R
T | T U V W X Y Z A B C D E F G H I J K L M N O P Q R S
U | U V W X Y Z A B C D E F G H I J K L M N O P Q R S T
V | V W X Y Z A B C D E F G H I J K L M N O P Q R S T U
W | W X Y Z A B C D E F G H I J K L M N O P Q R S T U V
X | X Y Z A B C D E F G H I J K L M N O P Q R S T U V W
Y | Y Z A B C D E F G H I J K L M N O P Q R S T U V W X
Z | Z A B C D E F G H I J K L M N O P Q R S T U V W X Y
```

*easy1.py*:

```python3
import itertools

alphabets = tuple(map(chr, range(ord('A'), ord('Z') + 1)))
alpha_mtx = tuple(itertools.product(alphabets, alphabets))
lookup_tbl = { k : alphabets[(alphabets.index(k[0]) + alphabets.index(k[1])) % len(alphabets)] for k in alpha_mtx}

key = "SOLVECRYPTO"
msg = "UFJKXQZQUNB"

flag = ""

for i, m in enumerate(msg):
    for v in alphabets:
        if lookup_tbl[(v, key[i])] == m:
            flag += v
            continue

print(flag)

# => CRYPTOISFUN
```

### caesar (100 points)

Decrypt this message. You can find the ciphertext in `/problems/caesar_1_4c9d445f770c71bd84ab0d822197a005` on the shell server.

FLAG: `picoCTF{crossingtherubiconwmanvbbo}`

*message:*

```text
picoCTF{zolppfkdqeboryfzlktjxksyyl}
```

```text
# Modify the code in rot13.py a little bit and we can get the following
# => crossingtherubiconwmanvbbo
```

### Flags (200 points)

What do the flags mean?

FLAG: `PICOCTF{F1AG5AND5TUFF}`

![flags](./flags.png)

This message is encoded using the marine flag system. The encoding is as follows:

![marine flag](./marine_flag.png)

Hence, the whole message should be `PICOCTF{F1AG5AND5TUFF}`.

### Mr-Worldwide (200 points)

A musician left us a message. What's it mean?

FLAG: `picoCTF{KODIAK_ALASKA}`

```text
picoCTF{(35.028309, 135.753082)(46.469391, 30.740883)(39.758949, -84.191605)(41.015137, 28.979530)(24.466667, 54.366669)(3.140853, 101.693207)_(9.005401, 38.763611)(-3.989038, -79.203560)(52.377956, 4.897070)(41.085651, -73.858467)(57.790001, -152.407227)(31.205753, 29.924526)}
```

```text
(35.028309, 135.753082)     Nakanocho, Kamigyo Ward, [K]yoto, Japan
(46.469391, 30.740883)      Odesa, [O]dessa Oblast, Ukraine, 65000
(39.758949, -84.191605)     [D]ayton, OH 45402
(41.015137, 28.979530)      European Side, Hoca Paşa, 34110 Fatih/[İ]stanbul, Turkey
(24.466667, 54.366669)      Hazza Bin Zayed the First St - [A]bu Dhabi - United Arab Emirates
(3.140853, 101.693207)      4MRV+87 Kuala Lumpur, Federal Territory of [K]uala Lumpur, Malaysia
(9.005401, 38.763611)       Kirkos, [A]ddis Ababa, Ethiopia
(-3.989038, -79.203560)     Av Nueva [L]oja, Loja, Ecuador
(52.377956, 4.897070)       Martelaarsgracht 5, 1012 TN [A]msterdam, Netherlands
(41.085651, -73.858467)     [S]leepy Hollow, NY 10591
(57.790001, -152.407227)    [K]odiak, AK 99615
(31.205753, 29.924526)      Faculty Of Engineering, [A]l Azaritah WA Ash Shatebi, Qism Bab Sharqi, Alexandria Governorate, Egypt
```

Although we can also try to use the `geocode` field of `https://geocode.xyz/` to solve it, it's not always the case.

```python3
import re
import requests
import json

def main():
    s = 'picoCTF{(35.028309, 135.753082)(46.469391, 30.740883)(39.758949, -84.191605)(41.015137, 28.979530)(24.466667, 54.366669)(3.140853, 101.693207)_(9.005401, 38.763611)(-3.989038, -79.203560)(52.377956, 4.897070)(41.085651, -73.858467)(57.790001, -152.407227)(31.205753, 29.924526)}'

    pat = re.compile(r'\(\-?\d+\.\d+, \-?\d+\.\d+\)')

    coordinates = re.findall(pat, s)

    partial_url = "https://geocode.xyz/{}?json=1"

    answer = ""

    for coordinate in coordinates:
        query = re.sub(r'(\(|\)|\s)', '', coordinate)

        # complete the url
        url = partial_url.format(query)

        while True:
            print(f"Sending request to {url}")
            response = requests.get(url)

            if (response.status_code == 200):
                json_obj = json.loads(response.text)
                answer += json_obj['geocode'][0]
                break

    for c in answer:
        s = pat.sub(c, s, 1)

    print()
    print(f"FLAG: {s}")

if __name__ == '__main__':
    main()

# => picoCTF{KODIAK_ALANKA}
```

### Tapping (200 points)

Theres tapping coming in from the wires. What's it saying `nc 2019shell1.picoctf.com 49914`.

FLAG: `PICOCTF{M0RS3C0D31SFUN903140448}`

Remove the curly braces and use the online Morse Decoder, we get the following:

```text
PICOCTFM0RS3C0D31SFUN903140448
```

### la cifra de (200 points)

I found this cipher in an old book. Can you figure out what it says? Connect with `nc 2019shell1.picoctf.com 39776`.

FLAG: `picoCTF{b311a50_0r_v1gn3r3_c1ph3r1119c336}`

*Encrypted message:*

```text
﻿Ne iy nytkwpsznyg nth it mtsztcy vjzprj zfzjy rkhpibj nrkitt ltc tnnygy ysee itd tte cxjltk

Ifrosr tnj noawde uk siyyzre, yse Bnretèwp Cousex mls hjpn xjtnbjytki xatd eisjd

Iz bls lfwskqj azycihzeej yz Brftsk ip Volpnèxj ls oy hay tcimnyarqj dkxnrogpd os 1553 my Mnzvgs Mazytszf Merqlsu ny hox moup Wa inqrg ipl. Ynr. Gotgat Gltzndtg Gplrfdo

Ltc tnj tmvqpmkseaznzn uk ehox nivmpr g ylbrj ts ltcmki my yqtdosr tnj wocjc hgqq ol fy oxitngwj arusahje fuw ln guaaxjytrd catizm tzxbkw zf vqlckx hizm ceyupcz yz tnj fpvjc hgqqpohzCZK{m311a50_0x_a1rn3x3_h1ah3x1119h336}

Ehk ktryy herq-ooizxetypd jjdcxnatoty ol f aordllvmlbkytc inahkw socjgex, bls sfoe gwzuti 1467 my Rjzn Hfetoxea Gqmexyt.

Tnj Gimjyèrk Htpnjc iy ysexjqoxj dosjeisjd cgqwej yse Gqmexyt Doxn ox Fwbkwei Inahkw.

Tn 1508, Ptsatsps Zwttnjxiax tnbjytki ehk xz-cgqwej ylbaql rkhea (g rltxni ol xsilypd gqahggpty) ysaz bzuri wazjc bk f nroytcgq nosuznkse ol yse Bnretèwp Cousex.

Gplrfdo’y xpcuso butvlky lpvjlrki tn 1555 gx l cuseitzltoty ol yse lncsz. Yse rthex mllbjd ol yse gqahggpty fce tth snnqtki cemzwaxqj, bay ehk fwpnfmezx lnj yse osoed qptzjcs gwp mocpd hd xegsd ol f xnkrznoh vee usrgxp, wnnnh ify bk itfljcety hizm paim noxwpsvtydkse.
```

This is **Vigenère cipher**. Use [this website](https://www.guballa.de/vigenere-solver) to decrypt it.

*Decrypted message:*

```text
It is interesting how in history people often receive credit for things they did not create

During the course of history, the Vigenère Cipher has been reinvented many times

It was falsely attributed to Blaise de Vigenère as it was originally described in 1553 by Giovan Battista Bellaso in his book La cifra del. Sig. Giovan Battista Bellaso

For the implementation of this cipher a table is formed by sliding the lower half of an ordinary alphabet for an apparently random number of places with respect to the upper halfpicoCTF{b311a50_0r_v1gn3r3_c1ph3r1119c336}

The first well-documented description of a polyalphabetic cipher however, was made around 1467 by Leon Battista Alberti.

The Vigenère Cipher is therefore sometimes called the Alberti Disc or Alberti Cipher.

In 1508, Johannes Trithemius invented the so-called tabula recta (a matrix of shifted alphabets) that would later be a critical component of the Vigenère Cipher.

Bellaso’s second booklet appeared in 1555 as a continuation of the first. The lower halves of the alphabets are now shifted regularly, but the alphabets and the index letters are mixed by means of a mnemonic key phrase, which can be different with each correspondent.
```

Hence, the ciphertext is encrypted with `key=flag`.

### rsa-pop-quiz (200 points)

Class, take your seats! It's PRIME-time for a quiz... `nc 2019shell1.picoctf.com 48028`.

FLAG: `picoCTF{wA8_th4t$_ill3aGal..o4d21b3ca}`

*rsa.py*:

```python3
from Crypto.Util.number import inverse


def printBanner(s):
    print("=" * 40 + " " + s + " " + "=" * 40)


def main():
    # QUESTION 1: YES
    printBanner("QUESTION 1")
    print(f"ANSWER: YES")
    p = 76753
    q = 60413
    n = p * q
    print(f"n = {n}")

    # QUESTION 2: YES
    printBanner("QUESTION 2")
    print(f"ANSWER: YES")
    p = 54269
    n = 5051846941
    q = n // p
    print(f"q = {q}")

    # QUESTION 3: NO
    printBanner("QUESTION 3")
    print(f"ANSWER: NO")
    # e = 3
    # n = 12738162802910546503821920886905393316386362759567480839428456525224226445173031635306683726182522494910808518920409019414034814409330094245825749680913204566832337704700165993198897029795786969124232138869784626202501366135975223827287812326250577148625360887698930625504334325804587329905617936581116392784684334664204309771430814449606147221349888320403451637882447709796221706470239625292297988766493746209684880843111138170600039888112404411310974758532603998608057008811836384597579147244737606088756299939654265086899096359070667266167754944587948695842171915048619846282873769413489072243477764350071787327913
    # p = ?
    # q = ?

    # QUESTION 4: YES
    printBanner("QUESTION 4")
    print(f"ANSWER: YES")
    p = 12611
    q = 66347
    tot = (p - 1) * (q - 1)
    print(f"totient(n) = {tot}")

    # QUESTION 5: YES
    printBanner("QUESTION 5")
    print(f"ANSWER: YES")
    pt = 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
    e = 3
    n = 29129463609326322559521123136222078780585451208149138547799121083622333250646678767769126248182207478527881025116332742616201890576280859777513414460842754045651093593251726785499360828237897586278068419875517543013545369871704159718105354690802726645710699029936754265654381929650494383622583174075805797766685192325859982797796060391271817578087472948205626257717479858369754502615173773514087437504532994142632207906501079835037052797306690891600559321673928943158514646572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
    ct = pow(pt, e, n)
    print(f"cipher text = {ct}")

    # QUESTION 6: NO
    printBanner("QUESTION 6")
    print(f"ANSWER: NO")
    # ct = 107524013451079348539944510756143604203925717262185033799328445011792760545528944993719783392542163428637172323512252624567111110666168664743115203791510985709942366609626436995887781674651272233566303814979677507101168587739375699009734588985482369702634499544891509228440194615376339573685285125730286623323
    # e = 3
    # n = 27566996291508213932419371385141522859343226560050921196294761870500846140132385080994630946107675330189606021165260590147068785820203600882092467797813519434652632126061353583124063944373336654246386074125394368479677295167494332556053947231141336142392086767742035970752738056297057898704112912616565299451359791548536846025854378347423520104947907334451056339439706623069503088916316369813499705073573777577169392401411708920615574908593784282546154486446779246790294398198854547069593987224578333683144886242572837465834139561122101527973799583927411936200068176539747586449939559180772690007261562703222558103359
    # pt = ?

    # QUESTION 7: YES
    printBanner("QUESTION 7")
    print(f"ANSWER: YES")
    p = 97846775312392801037224396977012615848433199640105786119757047098757998273009741128821931277074555731813289423891389911801250326299324018557072727051765547115514791337578758859803890173153277252326496062476389498019821358465433398338364421624871010292162533041884897182597065662521825095949253625730631876637
    q = 92092076805892533739724722602668675840671093008520241548191914215399824020372076186460768206814914423802230398410980218741906960527104568970225804374404612617736579286959865287226538692911376507934256844456333236362669879347073756238894784951597211105734179388300051579994253565459304743059533646753003894559
    e = 65537
    tot = (p - 1) * (q - 1)
    d = inverse(e, tot)
    print(f"d = {d}")

    # QUESTION 8: YES
    printBanner("QUESTION 8")
    print(f"ANSWER: YES")
    p = 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
    e = 65537
    n = 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239
    ct = 11414354166074402755164590556641179510390955987180616313598814488860571850569627408904290135283428920666717612247935936889741174861740224415910111160498656256896678079471373793134970331695671979818719947249086183419374170380011838377712137156655353333603309532154429629316613952073734543526935095731152872812955954824132637944535153824014078120443101933069681669256602347092095050923741698741934906694415931234676691035622479817210233347697548820214251179785631792488566945306938417118918268033241877748155382065658575003275681795893749615704427227208993357057762628133230351866198772974377028377937056546764806501336
    q = n // p
    tot = (p - 1) * (q - 1)
    d = inverse(e, tot)
    pt = pow(ct, d, n)
    print(f"plain text = {pt}")


if __name__ == '__main__':
    main()

```

```bash
shell:~$ nc 2019shell1.picoctf.com 48028
Good morning class! It's me Ms. Adleman-Shamir-Rivest
Today we will be taking a pop quiz, so I hope you studied. Cramming just will not do!
You will need to tell me if each example is possible, given your extensive crypto knowledge.
Inputs and outputs are in decimal. No hex here!
#### NEW PROBLEM ####
q : 60413
p : 76753
##### PRODUCE THE FOLLOWING ####
n
IS THIS POSSIBLE and FEASIBLE? (Y/N):Y
#### TIME TO SHOW ME WHAT YOU GOT! ###
n: 4636878989
Outstanding move!!!


#### NEW PROBLEM ####
p : 54269
n : 5051846941
##### PRODUCE THE FOLLOWING ####
q
IS THIS POSSIBLE and FEASIBLE? (Y/N):Y
#### TIME TO SHOW ME WHAT YOU GOT! ###
q: 93089
Outstanding move!!!


#### NEW PROBLEM ####
e : 3
n : 127381628029105465038219208869053933163863627595674808394284565252242264451730316353066837261825224949108085189204090194140348144093300942458257496809132045668323377047001659931988970297957869691242321388697846262025013661359752238272
8781232625057714862536088769893062550433432580458732990561793658111639278468433466420430977143081444960614722134988832040345163788244770979622170647023962529229798876649374620968488084311113817060003988811240441131097475853260399860805700
8811836384597579147244737606088756299939654265086899096359070667266167754944587948695842171915048619846282873769413489072243477764350071787327913
##### PRODUCE THE FOLLOWING ####
q
p
IS THIS POSSIBLE and FEASIBLE? (Y/N):N
Outstanding move!!!


#### NEW PROBLEM ####
q : 66347
p : 12611
##### PRODUCE THE FOLLOWING ####
totient(n)
IS THIS POSSIBLE and FEASIBLE? (Y/N):Y
#### TIME TO SHOW ME WHAT YOU GOT! ###
totient(n): 836623060
Outstanding move!!!


#### NEW PROBLEM ####
plaintext : 6357294171489311547190987615544575133581967886499484091352661406414044440475205342882841236357665973431462491355089413710392273380203038793241564304774271529108729717
e : 3
n : 291294636093263225595211231362220787805854512081491385477991210836223332506466787677691262481822074785278810251163327426162018905762808597775134144608427540456510935932517267854993608282378975862780684198755175430135453698717041597181
0535469080272664571069902993675426565438192965049438362258317407580579776668519232585998279779606039127181757808747294820562625771747985836975450261517377351408743750453299414263220790650107983503705279730669089160055932167392894315851464
6572885986881016569647357891598545880304236145548059520898133142087545369179876065657214225826997676844000054327141666320553082128424707948750331
##### PRODUCE THE FOLLOWING ####
ciphertext
IS THIS POSSIBLE and FEASIBLE? (Y/N):Y
#### TIME TO SHOW ME WHAT YOU GOT! ###
ciphertext: 2569312466317827143572415565824419919934373998541613726463186590209943298435243065708182936024924853853370296978198371821698188168214614860188028949368012576293754285447529706308706311663557112548484658622077650512262825417481
7453599031455247154693653633039789290720794344889707377201598609777044361654046647124543811715715278324665440166826732313645012228798361285117154578416813223020872623888186140797691785024811080572430042171282740106396311742371879788714476
0360749619552577176382615108244813
Outstanding move!!!


#### NEW PROBLEM ####
ciphertext : 107524013451079348539944510756143604203925717262185033799328445011792760545528944993719783392542163428637172323512252624567111110666168664743115203791510985709942366609626436995887781674651272233566303814979677507101168587739375699009734588985482369702634499544891509228440194615376339573685285125730286623323
e : 3
n : 27566996291508213932419371385141522859343226560050921196294761870500846140132385080994630946107675330189606021165260590147068785820203600882092467797813519434652632126061353583124063944373336654246386074125394368479677295167494332556053947231141336142392086767742035970752738056297057898704112912616565299451359791548536846025854378347423520104947907334451056339439706623069503088916316369813499705073573777577169392401411708920615574908593784282546154486446779246790294398198854547069593987224578333683144886242572837465834139561122101527973799583927411936200068176539747586449939559180772690007261562703222558103359
##### PRODUCE THE FOLLOWING ####
plaintext
IS THIS POSSIBLE and FEASIBLE? (Y/N):N
Outstanding move!!!


#### NEW PROBLEM ####
q : 92092076805892533739724722602668675840671093008520241548191914215399824020372076186460768206814914423802230398410980218741906960527104568970225804374404612617736579286959865287226538692911376507934256844456333236362669879347073756238894784951597211105734179388300051579994253565459304743059533646753003894559
p : 97846775312392801037224396977012615848433199640105786119757047098757998273009741128821931277074555731813289423891389911801250326299324018557072727051765547115514791337578758859803890173153277252326496062476389498019821358465433398338364421624871010292162533041884897182597065662521825095949253625730631876637
e : 65537
##### PRODUCE THE FOLLOWING ####
d
IS THIS POSSIBLE and FEASIBLE? (Y/N):Y
#### TIME TO SHOW ME WHAT YOU GOT! ###
d: 1405046269503207469140791548403639533127416416214210694972085079171787580463776820425965898174272870486015739516125786182821637006600742140682552321645503743280670839819078749092730110549881891271317396450158021688253989767145578723458252769465545504142139663476747479225923933192421405464414574786272963741656223941750084051228611576708609346787101088759062724389874160693008783334605903142528824559223515203978707969795087506678894006628296743079886244349469131831225757926844843554897638786146036869572653204735650843186722732736888918789379054050122205253165705085538743651258400390580971043144644984654914856729
Outstanding move!!!


#### NEW PROBLEM ####
p : 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
ciphertext : 11414354166074402755164590556641179510390955987180616313598814488860571850569627408904290135283428920666717612247935936889741174861740224415910111160498656256896678079471373793134970331695671979818719947249086183419374170380011838377712137156655353333603309532154429629316613952073734543526935095731152872812955954824132637944535153824014078120443101933069681669256602347092095050923741698741934906694415931234676691035622479817210233347697548820214251179785631792488566945306938417118918268033241877748155382065658575003275681795893749615704427227208993357057762628133230351866198772974377028377937056546764806501336
e : 65537
n : 23952937352643527451379227516428377705004894508566304313177880191662177061878993798938496818120987817049538365206671401938265663712351239785237507341311858383628932183083145614696585411921662992078376103990806989257289472590902167457302888198293135333083734504191910953238278860923153746261500759411620299864395158783509535039259714359526738924736952759753503357614939203434092075676169179112452620687731670534906069845965633455748606649062394293289967059348143206600765820021392608270528856238306849191113241355842396325210132358046616312901337987464473799040762271876389031455051640937681745409057246190498795697239
##### PRODUCE THE FOLLOWING ####
plaintext
IS THIS POSSIBLE and FEASIBLE? (Y/N):Y
#### TIME TO SHOW ME WHAT YOU GOT! ###
plaintext: 14311663942709674867122208214901970650496788151239520971623411712977119700648325685123965309
Outstanding move!!!


If you convert the last plaintext to a hex number, then ascii, you'll find what you need! ;)

shell:~$
```

```python3
>>> bytes.fromhex(format(14311663942709674867122208214901970650496788151239520971623411712977119700648325685123965309, 'x')).decode('utf-8')
# => picoCTF{wA8_th4t$_ill3aGal..o4d21b3ca}
```

### miniRSA (300 points)

Lets decrypt this: ciphertext? Something seems a bit small.

FLAG: `picoCTF{n33d_a_lArg3r_e_11db861f}`

```text

N: 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673
e: 3

ciphertext (c): 2205316413931134031074603746928247799030155221252519872649602375643231006596573791863783976856797977916843724727388379790172135717557077760267874464115099065405422557746246682213987550407899612567166189989232143975665175662662107329564517

```

The problem with `e` and `plaintext` being too small relatively to `n` is that:

```text
ciphertext = pow(plaintext, e) % n = pow(plaintext, e)
=> plaintext = log_e(ciphertext)
```

NOTE: For Mac users, in order to install `gmpy2`, we need to first use brew to install `mpfr` and `libmpc`.

```python3
import gmpy2

n = 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673
e = 3
ct = 2205316413931134031074603746928247799030155221252519872649602375643231006596573791863783976856797977916843724727388379790172135717557077760267874464115099065405422557746246682213987550407899612567166189989232143975665175662662107329564517

gct = gmpy2.mpz(ct)
# gn = gmpy2.mpz(n)
ge = gmpy2.mpz(e)

root, exact = gmpy2.iroot(gct, ge)
print(bytes.fromhex(format(root, 'x')).decode('utf-8'))
# => picoCTF{n33d_a_lArg3r_e_11db861f}
```

### waves over lambda (300 points)

We made alot of substitutions to encrypt this. Can you decrypt it? Connect with `nc 2019shell1.picoctf.com 21903`.

FLAG: `picoCTF{frequency_is_c_over_lambda_vlnhnasstm}`

```text
-------------------------------------------------------------------------------
cnqmofxg yeoe ug snlo zafm - zoekleqcs_ug_c_njeo_afitpf_jaqyqfggxi
-------------------------------------------------------------------------------
yfjuqm yfp gnie xuie fx is pugvngfa dyeq uq anqpnq, u yfp juguxep xye touxugy ilgeli, fqp ifpe gefocy finqm xye tnnrg fqp ifvg uq xye autofos oemfopuqm xofqgsajfquf; ux yfp gxolcr ie xyfx gnie znoerqndaepme nz xye cnlqxos cnlap yfopas zfua xn yfje gnie uivnoxfqce uq pefauqm duxy f qntaeifq nz xyfx cnlqxos. u zuqp xyfx xye pugxoucx ye qfiep ug uq xye ehxoeie efgx nz xye cnlqxos, wlgx nq xye tnopeog nz xyoee gxfxeg, xofqgsajfquf, inapfjuf fqp tlrnjuqf, uq xye iupgx nz xye cfovfxyufq inlqxfuqg; nqe nz xye duapegx fqp aefgx rqndq vnoxunqg nz elonve. u dfg qnx ftae xn aumyx nq fqs ifv no dnor mujuqm xye ehfcx ancfauxs nz xye cfgxae pofclaf, fg xyeoe foe qn ifvg nz xyug cnlqxos fg sex xn cnivfoe duxy nlo ndq nopqfqce glojes ifvg; tlx u znlqp xyfx tugxouxb, xye vngx xndq qfiep ts cnlqx pofclaf, ug f zfuoas deaa-rqndq vafce. u gyfaa eqxeo yeoe gnie nz is qnxeg, fg xyes ifs oezoegy is ieinos dyeq u xfar njeo is xofjeag duxy iuqf.
```

Use frequency analysis. Go to [this website](https://www.quipqiup.com/) to decrypt the message.

```text
congrats here is your flag - frequency_is_c_over_lambda_vlnhnasstm having had some time at my disposal when in london, i had visited the british museum, and made search among the books and maps in the library regarding transylvania; it had struck me that some foreknowledge of the country could hardly fail to have some importance in dealing with a nobleman of that country. i find that the district he named is in the extreme east of the country, just on the borders of three states, transylvania, moldavia and bukovina, in the midst of the carpathian mountains; one of the wildest and least known portions of europe. i was not able to light on any map or work giving the exact locality of the castle dracula, as there are no maps of this country as yet to compare with our own ordnance survey maps; but i found that bistritz, the post town named by count dracula, is a fairly well-known place. i shall enter here some of my notes, as they may refresh my memory when i talk over my travels with mina.
```

### b00tl3gRSA2 (400 points)

In RSA d is alot bigger than e, why dont we use d to encrypt instead of e? Connect with `nc 2019shell1.picoctf.com 10814`.

FLAG: `picoCTF{bad_1d3a5_4986370}`

*message:*

```text
c: 62184417101943249390536548122782080977356599035997302574376880537482381554858897365887269695404188786294349796991984193789883594283864335007196590972036943430997138981146440715584619005245379762102004137077753169791864298561229275338052509902860500343841423361993244744836154381168928976840915826792643224015
n: 128949474997714784368113704808455226929434851101345008102995587704589326730818822477695491718430186567077219057982598842134709371363883750221031058490887087971254523824570887870062702958485726133498613427248170383846849932286299813468034292671307845194264823707573660016150671413698559120758978445191898735963
e: 78103199872351318575648465940943745257853066427634620087102092771009861979948016513604872724767478764364102880916417612013630292755075231777832794708268032619025272619305862177820896074713878625330810458773724256529523534048200314310870188963097504090913438420320744686739256825363998764281670991011089190473
```

If the private component `d` is too small, the RSA scheme will be susceptible to Wiener's Attack.

For this problem, we can first check `d=3` and `d=65537`. (Although `d=65537`)

The more reliable way should be using RsaCtfTool.

```bash
$ python3 RsaCtfTool-master/RsaCtfTool.py -h
usage: RsaCtfTool.py [-h] [--publickey PUBLICKEY] [--createpub] [--dumpkey] [--ext] [--uncipherfile UNCIPHERFILE]
                     [--uncipher UNCIPHER] [--verbose] [--private] [--ecmdigits ECMDIGITS] [-n N] [-p P] [-q Q]
                     [-e E] [--key KEY]
                     [--attack {hastads,prime_n,factordb,pastctfprimes,mersenne_primes,noveltyprimes,smallq,wiener,comfact_cn,primefac,fermat,siqs,Pollard_p_1,londahl,all}]

RSA CTF Tool

optional arguments:
  -h, --help            show this help message and exit
  --publickey PUBLICKEY
                        public key file. You can use wildcards for multiple keys.
  --createpub           Take n and e from cli and just print a public key then exit
  --dumpkey             Just dump the RSA variables from a key - n,e,d,p,q
  --ext                 Extended dump of RSA private variables in --dumpkey mode - dp,dq,pinv,qinv).
  --uncipherfile UNCIPHERFILE
                        uncipher a file
  --uncipher UNCIPHER   uncipher a cipher
  --verbose             verbose mode (display n, e, p and q)
  --private             Display private key if recovered
  --ecmdigits ECMDIGITS
                        Optionally an estimate as to how long one of the primes is for ECM method
  -n N                  Specify the modulus. format : int or 0xhex
  -p P                  Specify the first prime number. format : int or 0xhex
  -q Q                  Specify the second prime number. format : int or 0xhex
  -e E                  Specify the public exponent. format : int or 0xhex
  --key KEY             Specify the input key file in --dumpkey mode.
  --attack {hastads,prime_n,factordb,pastctfprimes,mersenne_primes,noveltyprimes,smallq,wiener,comfact_cn,primefac,fermat,siqs,Pollard_p_1,londahl,all}
                        Specify the attack mode.

$ python3 RsaCtfTool-master/RsaCtfTool.py --createpub -e 78103199872351318575648465940943745257853066427634620087102092771009861979948016513604872724767478764364102880916417612013630292755075231777832794708268032619025272619305862177820896074713878625330810458773724256529523534048200314310870188963097504090913438420320744686739256825363998764281670991011089190473 -n 128949474997714784368113704808455226929434851101345008102995587704589326730818822477695491718430186567077219057982598842134709371363883750221031058490887087971254523824570887870062702958485726133498613427248170383846849932286299813468034292671307845194264823707573660016150671413698559120758978445191898735963 > key.pub

$ cat key.pub
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKBgQC3oVFdMhpvoRv4jSPmzApH
Ko+y3q3GJaN+k1imP1vVbd0LjhJ5vF/ZvcJICiAlpWauJ7pMEz4IzzKaMDYOWpH8
sSOsXUTVuKTyRGzryLL71JXE4aa0+2HwWIq80fCQTAlYj8Ie+k8NL7Ds72Fnbmfn
2T8fFgros/yyOq3cK2glWwKBgG84/34yTb7VV4rJejhd18/ZIKaXp6t/urJ87tHr
SGVSoPNRvzEK/wd0n0thDq2erD3KBFX1xboyPZUUpHk3NHpRbAM3D2hxzcRlC/Aw
SXcpdtUCMtERhtqQi40PVRbxO/7Rtu9l/UUXIPkNC3lMKbjp/5e0gwaWWc0WEVL/
t45J
-----END PUBLIC KEY-----

$
```

```python3
>>> c = 62184417101943249390536548122782080977356599035997302574376880537482381554858897365887269695404188786294349796991984193789883594283864335007196590972036943430997138981146440715584619005245379762102004137077753169791864298561229275338052509902860500343841423361993244744836154381168928976840915826792643224015
>>> m = bytes.fromhex(format(c, 'x'))
>>> m
# => b"X\x8d\xb5ir\xc1\xc0a\xf9\x9e\xc1\x05p\xbe\x8b\xa2\x95ic\xb4\x970\x92\xf8L[\xf9\x82\r\x08\xa6\xba\xce'\xe5\xce\xc7\\[\xf0\xa1H\x84\xfan\xfbO\x05vu\ti\x0e\xdb\xcc\x12?#\x83\xa9r h\x84y\x8e/N9\x9e\x81m\x04j4\x00;\x89\x9a~J\xc8\x10\x1d6.\x03+Y:?A'*m\x98\xf0O\xbb[\xdb\x19\xb5rF\xe1E\x12W\x03\xc2x\x98'7\xad\x96\xe3\xa6\x83\xf3yN\xc0\xbdh\xe1\xcf"
>>> with open('ciphertext', 'bw') as f:
        f.write(m)

# => 128
```

```bash
$ cat ciphertext
???'???\[?H??n?Ovu??0??Li???#??r h?y?/N9??mj4;??~J?6.+Y:?A'*m??O?[??rF?EW?x?'7??㦃?yN??h??

$ xxd ciphertext
00000000: 588d b569 72c1 c061 f99e c105 70be 8ba2  X..ir..a....p...
00000010: 9569 63b4 9730 92f8 4c5b f982 0d08 a6ba  .ic..0..L[......
00000020: ce27 e5ce c75c 5bf0 a148 84fa 6efb 4f05  .'...\[..H..n.O.
00000030: 7675 0969 0edb cc12 3f23 83a9 7220 6884  vu.i....?#..r h.
00000040: 798e 2f4e 399e 816d 046a 3400 3b89 9a7e  y./N9..m.j4.;..~
00000050: 4ac8 101d 362e 032b 593a 3f41 272a 6d98  J...6..+Y:?A'*m.
00000060: f04f bb5b db19 b572 46e1 4512 5703 c278  .O.[...rF.E.W..x
00000070: 9827 37ad 96e3 a683 f379 4ec0 bd68 e1cf  .'7......yN..h..

$ python3 ./RsaCtfTool-master/RsaCtfTool.py  --publickey key.pub --private --uncipherfile ciphertext  --verbose
[*] Performing hastads attack.
[*] Performing prime_n attack.
[*] Performing factordb attack.
[*] Performing pastctfprimes attack.
[*] Loaded 71 primes
[*] Performing mersenne_primes attack.
[*] Performing noveltyprimes attack.
[*] Performing smallq attack.
[*] Performing wiener attack.
-----BEGIN RSA PRIVATE KEY-----
MIIB4gIBAAKBgQC3oVFdMhpvoRv4jSPmzApHKo+y3q3GJaN+k1imP1vVbd0LjhJ5
vF/ZvcJICiAlpWauJ7pMEz4IzzKaMDYOWpH8sSOsXUTVuKTyRGzryLL71JXE4aa0
+2HwWIq80fCQTAlYj8Ie+k8NL7Ds72Fnbmfn2T8fFgros/yyOq3cK2glWwKBgG84
/34yTb7VV4rJejhd18/ZIKaXp6t/urJ87tHrSGVSoPNRvzEK/wd0n0thDq2erD3K
BFX1xboyPZUUpHk3NHpRbAM3D2hxzcRlC/AwSXcpdtUCMtERhtqQi40PVRbxO/7R
tu9l/UUXIPkNC3lMKbjp/5e0gwaWWc0WEVL/t45JAgMBAAECQQDLvN+Rn8GqltGh
8CQTupSZgBXlUkm3Z+kLtN11pmVzjgHZxMOzFJdhd8Q1Gf/RzF4k9wGB+G37bo5I
4goNZuY/AkEA5rwCQjjH0V35Mv+WUvozHY93ejgCOBqvwaexSCrV43i5+NZCzDMY
Pqux/eUn4iLQt8fEFseDdqymDQ+GFm4R5QIDAQABAgMBAAECQQDG/W2fE1COWNkh
+8wlHb1pd7hU1eZyo//+hTcwGrMnN8suIvZ/4FDVhOfUlHFB8EuUoF9/pFa9GTux
0cSzSUhe
-----END RSA PRIVATE KEY-----
[+] Clear text : b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00picoCTF{bad_1d3a5_4986370}'
```

Ok, we got the flag.

**Note:** In order to use `RsaCtfTool.py`, we need to have `pycrypto`, `gmpy2`, and `sympy` installed.

### AES-ABC (400 points)

AES-ECB is bad, so I rolled my own cipher block chaining mechanism - Addition Block Chaining! You can find the source here: `aes-abc.py`. The AES-ABC flag is `body.enc.ppm`

*aes-abc.py:*

```python3
#!/usr/bin/env python

from Crypto.Cipher import AES
from key import KEY
import os
import math

BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))


def to_bytes(n):
    s = hex(n)
    s_n = s[2:]
    if 'L' in s_n:
        s_n = s_n.replace('L', '')
    if len(s_n) % 2 != 0:
        s_n = '0' + s_n
    decoded = s_n.decode('hex')

    pad = (len(decoded) % BLOCK_SIZE)
    if pad != 0:
        decoded = "\0" * (BLOCK_SIZE - pad) + decoded
    return decoded


def remove_line(s):
    # returns the header line, and the rest of the file
    return s[:s.index('\n') + 1], s[s.index('\n')+1:]


def parse_header_ppm(f):
    data = f.read()

    header = ""

    for i in range(3):
        header_i, data = remove_line(data)
        header += header_i

    return header, data


def pad(pt):
    padding = BLOCK_SIZE - len(pt) % BLOCK_SIZE
    return pt + (chr(padding) * padding)


def aes_abc_encrypt(pt):
    cipher = AES.new(KEY, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt))

    blocks = [ct[i * BLOCK_SIZE:(i+1) * BLOCK_SIZE] for i in range(len(ct) / BLOCK_SIZE)]
    iv = os.urandom(16)
    blocks.insert(0, iv)

    for i in range(len(blocks) - 1):
        prev_blk = int(blocks[i].encode('hex'), 16)
        curr_blk = int(blocks[i+1].encode('hex'), 16)

        n_curr_blk = (prev_blk + curr_blk) % UMAX
        blocks[i+1] = to_bytes(n_curr_blk)

    ct_abc = "".join(blocks)

    return iv, ct_abc, ct


if __name__=="__main__":
    with open('flag.ppm', 'rb') as f:
        header, data = parse_header_ppm(f)

    iv, c_img, ct = aes_abc_encrypt(data)

    with open('body.enc.ppm', 'wb') as fw:
        fw.write(header)
        fw.write(c_img)

```

*body.enc.ppm:*

![body.enc.ppm](./body.enc.png)

FLAG: `picoCTF{d0Nt_r0ll_yoUr_0wN_aES}`

Knowing the key, it is possible for us to reverse the encryption and decrypt the message as follows:

```python3
__author__ = 'Devon Chen'

# FLAG = picoCTF{d0Nt_r0ll_yoUr_0wN_aES}

BLOCK_SIZE = 16
UMAX = 256 ** BLOCK_SIZE

if __name__ == '__main__':

    f = open('body.enc.ppm', 'rb')

    data = f.read()
    header = b''
    for _ in range(3):
        i = data.find(b'\n')
        header += data[0:i+1]
        data = data[i+1:]

    blocks = [int(data[i:i+BLOCK_SIZE].hex(), 16) for i in range(0, len(data), BLOCK_SIZE)]
    blocks = [(blocks[i+1] - blocks[i]) % UMAX for i in range(len(blocks) - 1)]
    for i in range(len(blocks)):
        s = format(blocks[i], 'x')
        if len(s) % 2 != 0:
            s = '0' + s
        blocks[i] = bytes.fromhex(s)

    with open('flag.ppm', 'wb') as flag:
        flag.write(header)
        flag.write(b''.join(blocks))

    f.close()
```

As you can see, the decrypted image is like this:

*flag.ppm:*

![flag.ppm](./aes_abc_flag.png)

### b00tl3gRSA3 (450 points)

Why use p and q when I can use more? Connect with `nc 2019shell1.picoctf.com 45122`.

FLAG: `picoCTF{too_many_fact0rs_8024768}`

Once we connect to the server, we will see the following:

```bash
$ nc 2019shell1.picoctf.com 45122
c: 928578955028473644356789381666024062722034323228797183377346332180897385665794462100512294120125788070453011950197291403579469313249177592508136324909989197132327350914252857799764603999027550303640977582887744877827400516692953369103601617550021677081387344442157290361933817649607439353527340724900261160739911528641194691399315963422884183
n: 43427803384841675741795294286614281293038074243773627102620871168909551143168385118055932849082200373801934266814965113401318154516161214551810924318596307428425326637156566851701988189278924286775968204627465227849023498807260126455703099862553535038377216404596223846660693174745490660657995894910041074681671729524939220842907412725891492103
e: 65537
```

Note that the exact values of `c`, `n`, and `e` can change.

We can use the following Python script to decrypt the message:

```python3
#!/usr/bin/env python3
  
from functools import reduce
from Crypto.Util.number import inverse

c= 928578955028473644356789381666024062722034323228797183377346332180897385665794462100512294120125788070453011950197291403579469313249177592508136324909989197132327350914252857799764603999027550303640977582887744877827400516692953369103601617550021677081387344442157290361933817649607439353527340724900261160739911528641194691399315963422884183
n = 43427803384841675741795294286614281293038074243773627102620871168909551143168385118055932849082200373801934266814965113401318154516161214551810924318596307428425326637156566851701988189278924286775968204627465227849023498807260126455703099862553535038377216404596223846660693174745490660657995894910041074681671729524939220842907412725891492103
e = 65537

# Normal factorization is too slow
# Use website https://www.alpertron.com.ar/ECM.HTM
# facrtors below
factors = "8623 800013 × 8975 373863 × 9724 224229 × 9938 028509 × 10290 072713 × 10328 337413 × 10370 395489 × 10651 523033 × 10935 315851 × 11033 775793 × 11477 881169 × 12099 578609 × 12249 947209 × 12329 922797 × 12844 488721 × 12974 946793 × 13175 172481 × 13304 314817 × 13364 114299 × 13415 341447 × 14290 992883 × 14353 035209 × 14391 318289 × 14474 135807 × 14541 982717 × 14723 432513 × 14798 973337 × 15042 208169 × 15319 042603 × 15685 462669 × 16061 060441 × 16566 262627 × 16771 550063 × 17085 756097"

factors = list(map(lambda s: int(s), factors.replace(' ', '').split("×")))

tot = reduce(lambda rst, f: rst * (f - 1), factors, 1)
d = inverse(e, tot)

pt = pow(c, d, n)
pt = format(pt, 'x')
pt = [chr(int(pt[i:i+2], 16)) for i in range(0, len(pt), 2)]
pt = "".join(pt)

print(pt)

# => picoCTF{too_many_fact0rs_8024768}
```
