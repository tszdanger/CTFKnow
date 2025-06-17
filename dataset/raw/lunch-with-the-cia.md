## CIA  
### TL;DR  
Use Dynamic Programming, with a state of `[width, height]` and try all
reasonable cuts.

### Short Description  
Repeatedly cut a bar of choclate, in a way that:  
1. resulting pieces match one of the given forms  
2. the waste of those *not* matching is as low as possible

Important: Each cut is of the form: Take one piece and cut it with a single
straight horizontal or vertical cut into exactly two pieces. Just like
breaking the piece of chocolate.

```  
_____________  
|      |      |  
|______|      |  
|      |______|  
|______|      |  
|      |      |  
|______|______|  
_____________ <- aa  
|        |    |  
|________|    |  
|        |____|  
|________|    |  
|        |    |  
|________|____|  
|_____________|  
```

### Insights  
1. If you look at the final cutting pattern of the chocolate, there is (at least) one cut running entirely from top to bottom or left ro right( line a above). After this cut, there are two pieces, each of which has the same condition on its pattern. (Except for the smallest part)  
2. When we have two pieces, we can solve them individually and add their waste.  
3. To compute the waste, we only need the current dimensions of the piece. The history of breaking is unimportant.  
4. If we do a cut horizontally, one side can have an arbitrary height, but at least one side of the cut (above the red line) has a height that is the sum of some of our given reactangles' heights. (Or to be precise: It is always possible to find a cut like this where no better other option exists. Proof is best done manually on a paper. In short: we can slightly shift the cut position without changing the solution).

### Solution  
1. Start by computing all possible heights to cut (according to insight 4):  
	1. create an array `hs` of length `total_height+1` of type boolean. If the value is true, this height is the sum of some heights.  
	2. Mark `hs[0] = true` (height 0 is assumed to be valid)  
	3. Take the first rectangle with height `h`, go through the array `hs` and if `hs[i] == true` set  `hs[i + h] = true` as well (height `i` is ok, so `i+h` is ok as well. Now all multiples of `h` are marked as valid cuts.  
	4. Repeat the step (3) with the other rectangles on the same array.  
	5. We have marked all reasonable cutting heights  
	6. Run through the array one more time and store all `i`s where `hs[i] == true`.  
	7. Complexity of this is `O(height * |rectangles|)`  
	8. Do 1-7 again for the widths  
2. Now, assume we have a piece of dimensions `r x c`. If this is a valid rectangle already, the waste is 0. Otherwise, we try all possible heights from step 1, cut the piece and find the best solution for both subpieces. Of all those cuts, we take that one with the smallest sum of results of the subpieces. So, cutting at height h wastes: `waste_cut(r, c, cutheight) = waste(height, c) + waste(r - height, c)`. We try all vertical cuts as well. Of all those options, we take the best.  
3. There is one more important thing: The above is too slow because we compute many piece sizes multiple times. (e.g., a bar of size `3 x 8`is cut into `3 x 4`and `3 x 4`, we only need to compute the result for `3 x 4` once (insight 3). We can store the result and use it later if we come along an identical piece again. -> Memoization / Dynamic Programming. To do so, simply create a large 2-dimensional array `dp`with `r+1` rows and `c+1`columns. `dp[a][b]` is the minimal waste possible for a piece of dimensions `a x b`. Whenever you need to compute a rectangle, check if this is already computed and return it if yes.  
4. Complexity of this is `O(r x c x (|cut heights| + |cut widths|))`. Side note: If there is a rectangle of very small size, this will be too slow, because `|cut heights|` and `|cut widths|`will be huge. But the server's rectangles had the same magnitude than the chocolate.

### Implementation  
I had a python script to communicate with the server and a C++ code to compute
the answer (probably not needed, but , well..)  
This code is only the interesting parts of the C++ code. Note, that I did not
implement it recursivly as it is indicated above, but I fill the array `dp`
from left upper corner to the lower right corder. In this order, I ensure,
that the values I need are already computed beforehand and no check is needed.

```  
// compute all possible cutting heights. chs is the boolean array  
// fs[i] is the i'th rectangle. fs[i].first is its height, fs[i].second is its
width  
for (int x = 0; x < chs.size() - fs[i].first; x++) if (chs[x])
chs[x+fs[i].first] = true;  
for (int x = 0; x < cws.size() - fs[i].second; x++) if (cws[x])
cws[x+fs[i].second] = true;  
```

```  
ll solve(ll r, ll c) {  
	// dp is out array. dp[x][y] holds the best value for piece with size x * y (best = minimal waste)  
	// currently, the best option we know is wasting everything:  
	for (ll x = 1; x <= r; x++) for (ll y = 1; y <= c; y++) {  
		dp[x][y] = x * y;  
	}  
	// All pieces matching the rectangles perfectly have zero waste:  
	for (pll p : fs) dp[p.first][p.second] = 0;  
	// Now compute the minimal waste for each possible dimension (x * y)  
	for (ll x = 1; x <= r; x++) for (ll y = 1; y <= c; y++) {  
		// Try all possible vertical cuts  
		for (ll w : cutws) {  
			if (w > y) break; // cuting more than we have  
			// dp[x][y-w] is the best option for the right side (we already computed this and stored it in dp)  
			// dp[x][w] is the best option for the left side (we already computed this and stored it in dp)  
			dp[x][y] = min(dp[x][y], dp[x][y-w] + dp[x][w]);  
		}  
		// Try all possible horizontal cuts  
		for (ll h : cuths) {  
			if (h > x) break;  
			dp[x][y] = min(dp[x][y], dp[h][y] + dp[x-h][y]);  
		}  
	}  
	return dp[r][c];  
}  
```