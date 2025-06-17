## Challenge Description

A friend handed me this map and told me that it will lead me to the flag.  
It is confusing me and I don't know how to read it, can you help me out?

## Intuition

This challenge is quite interesting. You are given a secret (the flag) which
is  
encrypted with a password, and a hint for the password. An important detail is  
that the password is composed of a few uniquely and randomly chosen words  
**from the US constitution**, which is given to us.

Now for the hint. Consider that the password is string  
$s=s_1||s_2||\dots||s_n$, where for each $1 \le i \le n$, $s_i$ is a word from  
the US constitution and $||$ is string concatenation.

The hint is a graph build in the following way:  
1. for each word used in the password there is a corresponding vertex  
2. for each word $s_i$, with $1 \le i \< n$, we have an edge from $i$ to $i + 1$  
3. $n^{1.33}$ random edges are added  
4. each edge in the graph is finally reversed with a $50 \\%$ chance

Intuitively an exhausive search through a modified graph should give us the
right  
password, but we need to do some smart filtering of the solutions

## Solution

Our goal is to revese the given graph to find the password. We can obtain an  
undirected graph by adding for each edge an edge in the opposite direction.
The  
naive solution would just be a backtracking solution which tries attempts to
find  
all the possible solutions. This is way too time (and space) consuming so we
have to  
do better, in order to bypass the randomness added in step 3.

Since we know what words are used, we can enforce during our backtracking that  
at any point, if we haven't found a full word, each letter added leads to a  
prefix of a valid word and if a word is found, the next letter added either  
leads to a prefix of another word, or is the first letter of another word.

A very efficient way of keeping track of all of this is to use a trie, which
we  
fill up with all the words used for password generation.

This is the full code which generates all the possible passwords from the
graph:

```c++  
#include <fstream>  
#include <unordered_map>  
#include <unordered_set>  
#include <vector>  
#include <algorithm>  
#include <iostream>

using namespace std;

ifstream fin("./hint");  
ifstream fwords("./words");  
ofstream fout("solution.cpp.txt");

int n, m;  
unordered_map<int, int> coresp;

char labels[28];  
vector < int > gr[28];

struct trie_node {  
   trie_node(bool w) {  
       word = w;  
       for (int i = 0; i < 26; ++i) {  
           nxt[i] = nullptr;  
       }  
   }  
   bool word;  
   trie_node *nxt[26];  
} *root = new trie_node(0);

void insert(string s) {  
   trie_node *n = root;  
   for (const char &c : s) {  
       if (!n->nxt[c - 'a']) {  
           n->nxt[c - 'a'] = new trie_node(0);  
       }  
       n = n->nxt[c - 'a'];  
   }  
   n->word = 1;  
   cerr << s << '\n';  
}

void back(int node, trie_node *t, vector<bool> &used, string &sol) {  
   if (t->word) {  
       back(node, root, used, sol);  
   }  
   used[node] = true;  
   sol += labels[node];

   bool smth = false;  
   for (const int &x : gr[node]) {  
       if (used[x]) continue;  
       if (!t->nxt[labels[x] - 'a']) continue;  
       back(x, t->nxt[labels[x] - 'a'], used, sol);  
       smth = true;  
   }

   if (!smth && sol.size() == n && t->word) {  
       fout << sol << '\n';  
   }

   used[node] = false;  
   sol.pop_back();  
}

int main() {

   string s;  
   while (fwords >> s) {  
       insert(s);  
   }

   fin >> n >> m;

   for (int i = 0; i < n; ++i) {  
       int label;  
       fin >> label;  
       coresp[label] = i;  
       char val;  
       fin >> val;  
       labels[i] = val;  
   }

   for (int i = 0; i < m; ++i) {  
       int a, b;  
       fin >> a >> b;  
       gr[coresp[a]].push_back(coresp[b]);  
       gr[coresp[b]].push_back(coresp[a]);  
   }

   string sol = "";  
   vector<bool> used(n, 0);

   for (int i = 0; i < n; ++i) {  
       cerr << "start " << i << '\n';  
       if (!root->nxt[labels[i] - 'a']) continue;  
       back(i, root->nxt[labels[i] - 'a'], used, sol);  
       cerr << "done " << i << '\n';  
   }  
}  
```

This results in a file with many duplicates. Running `cat solution.cpp.txt |  
sort | uniq` leads to only 13 possible passwords. Using a simple script to try each one of them gets us the correct passwords and the flag.

   chosenstandardsignwatergiven is bad!  
   chosenstandardwatersigngiven is bad!  
   givenchosenstandardsignwater is bad!  
   givenchosenstandardwatersign is bad!  
   givenstandardsignwaterchosen is bad!  
   signgivenchosenstandardwater is bad!  
   signgivenstandardwaterchosen is bad!  
   signwatergivenchosenstandard is bad!  
   standardsignwatergivenchosen is bad!  
   found it: standardwatersigngivenchosen  
   b'CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}'  
   waterchosenstandardsigngiven is bad!  
   watergivenchosenstandardsign is bad!  
   watersigngivenchosenstandard is bad!

### Flag

`CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}`

Original writeup (https://dothidden.xyz/google_ctf_2023/npc/).