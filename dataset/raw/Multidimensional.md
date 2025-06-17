# multidimensional (140 solves, 442 points)

## Description:  
It's time to break through portals and get multidimensional! Can you cross
through all 3 (or 4?) dimensions?

[Multidimensional.java](Multidimensional.java)

## Solution:  
This challenge takes our input and does a bunch of manipulation and checks if
it equals `hey_since_when_was_time_a_dimension?`. So all we have to do is
reverse the functions and apply them to the checked string to get the flag. A
lot of it was just copying the function and changing a couple things to make
it do the opposite of the orginal file.

**Script:**  
```java  
public class Solve {  
	private static char[][] arr = new char[6][6];  
	public static void main(String[] args) {  
		int[][] t = {{8, 65, -18, -21, -15, 55},   
				{8, 48, 57, 63, -13, 5},   
				{16, -5, -26, 54, -7, -2},   
				{48, 49, 65, 57, 2, 10},   
				{9, -2, -1, -9, -11, -10},   
				{56, 53, 18, 42, -28, 5}};  
		String connolly = "hey_since_when_was_time_a_dimension?";  
		System.out.println("Start: ");  
		for (int x = 0; x < 6; x++) {  
			for (int y = 0; y < 6; y++) {  
				arr[x][y] = connolly.charAt(6 * x + y);  
			}  
		}  
		printArr(arr);  
		System.out.println("\nreversing time");  
		//reverse time  
		for (int j = 0; j < arr[0].length; j++) {  
			for (int i = 0; i < arr.length; i++) {  
				arr[i][j] -= t[j][i];  
			}  
		}  
		printArr(arr);  
		System.out.println("\nreversing space");  
		revSpace(35);  
		printArr(arr);  
		//reversing plane  
		System.out.println("\nreversing plane");  
		for (int i = 0; i < 6; i++) {  
			for (int j = 0; j < 6; j++) {  
				arr[i][j] -= i + 6 - j;  
			}  
		}  
		for (int i = 0; i < 3; i++) {  
			for (int j = 0; j < 3; j++) {  
				char temp = arr[i][j];   
				arr[i][j] = arr[5 - j][i];  
				arr[5 - j][i] = arr[5 - i][5 - j];  
				arr[5 - i][5 - j] = arr[j][5 -i];  
				arr[j][5 -i] = temp;  
  
			}  
		}  
		printArr(arr);

		//reverse line  
		System.out.println("\nreversing line");  
		char[][] newArr = new char[arr.length][arr[0].length];  
		for (int i = 0; i < arr.length; i++) {  
			for (int j = 0; j < arr[0].length; j++) {  
				int p = i - 1, q = j - 1, f = 0;  
				boolean row = i % 2 == 0;  
				boolean col = j % 2 == 0;  
				if (row) {  
					p = i + 1;  
					f++;  
				} else  
					f--;  
				if (col) {  
					q = j + 1;  
					f++;  
				} else  
					f--;  
				newArr[i][j] = (char) (arr[p][q] - f);  
			}  
		}  
		arr = newArr;  
		printArr(arr);  
		String ans = "";  
		for (int i = 0; i < 36; i++) {  
			ans += arr[i % 6][i / 6];  
		}  
		System.out.println(ans);  
	}  
	public static void revSpace(int n) {  
		arr[(35 - n) / 6][(35 - n) % 6] += (n / 6) + (n % 6);  
		if (n != 0) {  
			n--;  
			revSpace(n);  
		}  
	}  
	public static void printArr(char[][] array) {  
		for (int x = 0; x < 6; x++) {  
			for (int y = 0; y < 6; y++) {  
				System.out.print(array[x][y] + " ");  
			}  
			System.out.println("");  
		}  
	}

}  
```  
## Flag:  
`flag{th3_g4t3w4y_b3t233n_d1m3n510n5}`  

Original writeup (https://github.com/BASHing-thru-
challenges/HSCTF-2021-Writeups/tree/main/rev/multidimensional).