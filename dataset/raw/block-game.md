## block-game

> Points: 391  
>  
> Solves: 22

### Description:  
> I made a game with some blocks! I worked out how to save but I can't load my
> worlds back. It's ok, it wasn't that important anyway...

### Attachments:  
> chall.jar  
>  
> data.dat

## Analysis:

オプションなしで`java`を実行すると、下記の`java.lang.OutOfMemoryError`になるため、`-Xmx2000m`のオプションを追加して`java
-Xmx2000m -jar chall.jar`で実行しました。

```  
mito@ubuntu:~/CTF/TJCTF_2022/Reverse_block-game$ java -jar chall.jar  
Exception in thread "main" java.lang.OutOfMemoryError: Java heap space  
	at Game.<init>(Game.java:42)  
	at Main.main(Main.java:5)  
mito@ubuntu:~/CTF/TJCTF_2022/Reverse_block-game$ java -Xmx2000m -jar chall.jar  
FPS: 2  
FPS: 1  
FPS: 43  
FPS: 48  
FPS: 42  
FPS: 45  
FPS: 26  
FPS: 17  
FPS: 38  
```

![](https://github.com/mito753/CTF/blob/main/2022/TJCTF_2022/Reverse_block-
game/chall_click_before.png?raw=true)

`java`ファイルは下記サイトでデコンパイルしました。

[www.decompiler.com](http://www.decompiler.com)

デコンパイル結果の`Player.java`より、下記のキーが有効であることがわかりました。  
- ESC: 終了  
- P: データセーブ  
- W: 上に移動  
- S: 下に移動  
- A: 左に移動  
- D: 右に移動

```java  
  public void keyPressed(KeyEvent var1) {  
     this.keys.put(var1.getKeyCode(), true);  
     if (var1.getKeyCode() == 27) {  
        System.exit(0);  
     } else if (var1.getKeyCode() == 80) {  
        this.game.saveData();  
     }

  }

  public void keyReleased(KeyEvent var1) {  
     this.keys.put(var1.getKeyCode(), false);  
  }

  public void tick() {  
     if ((Boolean)this.keys.getOrDefault(87, false)) {  
        this.y -= 0.1D;  
     }

     if ((Boolean)this.keys.getOrDefault(83, false)) {  
        this.y += 0.1D;  
     }

     if ((Boolean)this.keys.getOrDefault(65, false)) {  
        this.x -= 0.1D;  
     }

     if ((Boolean)this.keys.getOrDefault(68, false)) {  
        this.x += 0.1D;  
     }

     this.x = Math.max(0.5D, Math.min(this.x, (double)this.game.getMapWidth() - 0.5D));  
     this.y = Math.max(0.5D, Math.min(this.y, (double)this.game.getMapHeight() - 0.5D));  
     Tile var1 = this.game.getTileAt((int)this.x, (int)this.y, this.z);  
     if (var1.getType() == Tile.TileType.STAIRS_DOWN) {  
        if (!this.onStairs && this.z > 0) {  
           --this.z;  
        }

        this.onStairs = true;  
     } else if (var1.getType() == Tile.TileType.STAIRS_UP) {  
        if (!this.onStairs && this.z < 7) {  
           ++this.z;  
        }

        this.onStairs = true;  
     } else {  
        this.onStairs = false;  
     }

  }  
```

## Solution:

マウスボタンをクリックするとブロックの色を変更することができます。この機能を使ってフラグを書いたと思いますが、どのように`data.dat`が変化するか下記の`java`コードでは不明なので、マウスボタンをクリックする前と後で`data.dat`を比較して確認しました。

![](https://github.com/mito753/CTF/blob/main/2022/TJCTF_2022/Reverse_block-
game/chall_click_after.png?raw=true)

```java  
  public void mouseClicked(MouseEvent var1) {  
  }

  public void mousePressed(MouseEvent var1) {  
     int var2 = (int)(((double)var1.getX() + this.getX() * 20.0D - (double)(this.game.getWidth() / 2)) / 20.0D);  
     int var3 = (int)(((double)var1.getY() + this.getY() * 20.0D - (double)(this.game.getHeight() / 2)) / 20.0D);  
     if (var1.getButton() == 3) {  
        this.build(var2, var3);  
     } else if (var1.getButton() == 1) {  
        this.destroy(var2, var3);  
     }

  }  
```

下記は`data.dat`のマウスクリック前後を比較するためのコードです。

```python  
f1 = open("data_click_before.dat", "rb")  
f2 = open("data_click_after.dat", "rb")

f1.read(17)  
f2.read(17)

for y in range(2000):  
 for x in range(3000):  
   b1 = f1.read(4)  
   b2 = f2.read(4)  
   if b1[0] != b2[0]:  
     print(y, x, "(", hex(b1[0]), hex(b2[0]), ") (", hex(b1[1]), hex(b2[1]), ") (", hex(b1[2]), hex(b2[2]), ") (", hex(b1[3]), hex(b2[3]), ")")  
```

`data.dat`は最初の`17`バイトがヘッダ情報で、それ以降は`4`バイトで１つのブロックに対応しています。

比較結果は下記になり、最初の`1`バイトのみ`0x0`から`0xf`などの変化がありました。  
このことから与えられた`data.dat`の`1`バイト目の`2`から`4`ビット目が`1`になっているものを探せばフラグを再現できると思いました。

```  
mito@ubuntu:~/CTF/TJCTF_2022/Reverse_block-game$ python3 diff.py  
996 1498 ( 0x0 0xf ) ( 0x0 0x0 ) ( 0x3 0x3 ) ( 0x40 0x40 )  
996 1499 ( 0x0 0xf ) ( 0x0 0x0 ) ( 0x3 0x3 ) ( 0x20 0x20 )  
996 1500 ( 0x10 0x1f ) ( 0x0 0x0 ) ( 0x30 0x30 ) ( 0x43 0x43 )  
996 1501 ( 0x10 0x1f ) ( 0x0 0x0 ) ( 0x33 0x33 ) ( 0x40 0x40 )  
996 1502 ( 0x10 0x1f ) ( 0x1 0x1 ) ( 0x30 0x30 ) ( 0xb3 0xb3 )  
997 1497 ( 0x1 0xf ) ( 0x0 0x0 ) ( 0x30 0x30 ) ( 0x40 0x40 )  
997 1498 ( 0x0 0xf ) ( 0x10 0x10 ) ( 0x33 0x33 ) ( 0x40 0x40 )  
997 1499 ( 0x0 0xf ) ( 0x0 0x0 ) ( 0x33 0x33 ) ( 0x43 0x43 )  
997 1500 ( 0x0 0xf ) ( 0x0 0x0 ) ( 0x30 0x30 ) ( 0x43 0x43 )  
997 1501 ( 0x1 0xf ) ( 0x0 0x0 ) ( 0x30 0x30 ) ( 0x43 0x43 )  
997 1502 ( 0x0 0xf ) ( 0x1 0x1 ) ( 0x33 0x33 ) ( 0x43 0x43 )  
...  
```

しかしながら`2`から`4`ビット目が`1`ではヒットしなかったので、`2`ビット目のみを`1`で判定したところフラグを表示できました。

```python  
from PIL import Image  
im = Image.new('RGB', (3000,2000))  
f = open("data.dat", "rb")  
f.read(17)

for y in range(2000):  
 for x in range(3000):  
   b = f.read(4)  
   if (ord(b[0])>>1)&1 == 0x1:  
     r1 = g1 = b1 = 0  
   else:  
     r1 = g1 = b1 = 255  
   im.putpixel((x,y), (r1,g1,b1))

im.save('flag.png')  
```

## Results:  
下記は作成した`flag.png`の中央部分を拡大した結果です。

![](https://github.com/mito753/CTF/blob/main/2022/TJCTF_2022/Reverse_block-
game/flag_exp.png?raw=true)

Original writeup
(https://github.com/mito753/CTF/tree/main/2022/TJCTF_2022/Reverse_block-game).