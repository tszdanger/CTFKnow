[中文](./README_zh.md) [English](./README.md)

## Mine Sweeping

>source unity project : `Mine Sweeping Unity`  
>  
>problem : `Mine Sweeping Exe\Mine Sweeping.exe`

### Analysis

Elements.cs  
```C#  
class Elements: MonoBehaviour  
{  
   void Awake()  
   {  
       int x = (int)transform.position.x;  
       int y = (int)transform.position.y;  
       //According to the global array to set whether the grid is mine or open space  
       bIsMine = (((MayWorldBeAtPeace[x, y] ^ AreYouFerryMen[x, y]) - 233) / 2333) == 1 ? true : false;  
       //Bind the object instance to the grid according to the position of the grid  
       Grids._instance.eleGrids[(int)transform.position.x, (int)transform.position.y] = this;  
       //The corresponding grid value setting in the grid  
       Grids._instance.DevilsInHeaven[(int)transform.position.x, (int)transform.position.y] = (bIsMine == true ? 1 : 0);  
       //Hide the reset button  
       resetButton = GameObject.FindGameObjectWithTag("resetButton");  
       if (resetButton)  
           resetButton.SetActive(false);  
   }

   // Start is called before the first frame update  
   void Start()  
   {  
       //Confusion map when initializing  
       Grids._instance.ChangeMap();  
       //For test only  
       //DawnsLight();  
   }  
   ...  
   void OnMouseUpAsButton()  
   {  
       //mouse click on the corresponding grid trigger  
       if (!Grids._instance.bGameEnd && !bIsOpen)  
       {   //not open yet  
           //set it open  
           bIsOpen = true;  
           int nX = (int)transform.position.x;  
           int nY = (int)transform.position.y;  
           if (bIsMine)  
           {  
               //show mine  
               SafeAndThunder(0);  
               Grids._instance.bGameEnd = true;  
               //game lose  
               Grids._instance.GameLose();  
               print("game over: lose");  
           }  
           else  
           {  
               //not the mine, show the number of mines around + open the adjacent grid without any mine around  
               int adjcentNum = Grids._instance.CountAdjcentNum(nX, nY);  
               SafeAndThunder(adjcentNum);  
               Grids._instance.Flush(nX, nY, new bool[Grids.w, Grids.h]);  
           }  
           if (Grids._instance.GameWin())  
           {  
               //game win  
               Grids._instance.bGameEnd = true;  
               print("game over: win");  
           }  
       }  
   }  
}  
```  
Elements.cs is a script that hangs on each grid.  
`Awake` determines whether the grid is a mine or an open space.  
In `Start`, the six swing but fixed positions in the map are randomized.  
`OnMouseUpAsButton` detects whether the current grid is a mine and performs
corresponding processing.

Grid.cs  
```C#  
   public bool GameWin()  
   {  
       foreach (Elements ele in eleGrids)  
       {  
           if (!ele.bIsOpen && !ele.bIsMine)  
           {   //exist any grid which is not mine  
               return false;  
           }  
       }  
       foreach (Elements ele in eleGrids)  
       {   //load the QR code  
           ele.DawnsLight();  
       }  
       return true;  
   }

   public void ChangeMap()  
   {  
       System.Random ran = new System.Random((int)System.DateTime.Now.Millisecond);  
       const int SwingNum = 6;  
       const int Start = 0;  
       const int End = 100;  
       int[] SwingPosX = new int[SwingNum]{ 9, 15, 21, 10, 18, 12, };  
       int[] SwingPosY = new int[SwingNum]{ 0, 7, 15, 3, 16, 28 };  
       int[] RandomNum = new int[SwingNum];  
       for (int i = 0; i < SwingNum; i++)  
       {  
           RandomNum[i] = ran.Next(Start, End);  
       }

       for (int i = 0; i < SwingNum; i++)  
       {  
           int x = SwingPosX[i];  
           int y = SwingPosY[i];  
           eleGrids[x, y].bIsMine = RandomNum[i] > 60 ? false : true ;  
           DevilsInHeaven[x, y] = eleGrids[x, y].bIsMine == true ? 1 : 0;  
       }  
   }  
```  
Grid.cs is a script that controls all grids. The main thing is to detect
whether the game wins or loses and presses the reset button. The ChangeMap
function randomizes the 01 of the swing bits to confuse the game.

### exp  
1. Just record: every time you click on the mine, record the position of the mine. Anyway, the reset button will only turn the grid to be not open, and will not change the 01 value of the grid. 30 minutes is enough.  
2. Reverse: analyze Elements.cs, know that whether each grid is mine is determined by the global array, and then the global array `MayWorldBeAtPeace` and `AreYouFerryMen` can be processed accordingly.  
3. Dynamic debugging: after the game goes in, check the Grid.cs, which is used to save the game data so that the reset button executes the `DevilsInHeaven` array.  
4. Change the code: modify the if statement of the game to win or lose in Grid.cs, and load the last QR code directly.  

Original writeup (https://github.com/De1ta-
team/De1CTF2019/tree/master/writeup/misc/Mine%20Sweeping).