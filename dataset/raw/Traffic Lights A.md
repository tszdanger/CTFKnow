# Traffic Lights A Writeup

This challenge can be quickly identified as a textbook min cost flow problem.  
Googling "min cost flow code" we find a handy implementation of this
algorithm.  
 [Their code](https://developers.google.com/optimization/flow/mincostflow)

Shamelessly being a script kiddie and copying their code, we only have to
change how we read in input to solve the problem.

Sidenote: This problem was solved while there was still the issue of there
being a greater total workplace capacity than total workers.  
Therefore, we had to call min_cost_flow.SolveMaxFlowWithMinCost() instead of
just Solve(), as seen in Google's documentation.

From here, the only challenge left is to successfully pipe the output. But
that's for noobs. Instead, I appended the problem input into a Notepad++ file,
cut the garbage, copied the input over to an input file for python, ran the
code using pycharm, and pasted the output back into the terminal. Only took
two tries to get this under 120 seconds.

Flag:  
```flag{n0_u_c4n7_ju57_u53_n37w0rk_51mpl3x_h4h4_c4r_60_vr00m_69bb3a80}```

Code below  
```python  
from __future__ import print_function  
from ortools.graph import pywrapgraph  
import numpy as np  
from sys import stdin

def main():  
	"""MinCostFlow simple interface example."""  
	fileIn = open('TrafficA.in', 'r')  
	while True:  
		#while st.find("Here") < 0:  
		#	st = stdin.readline()  
		#	print(st, file = fileOut)   
		st = fileIn.readline()  
		n,m,k,l = (int(s) for s in st.split())  
		# Define four parallel arrays: start_nodes, end_nodes, capacities, and unit costs  
		# between each pair. For instance, the arc from node 0 to node 1 has a  
		# capacity of 15 and a unit cost of 4.  
  
		start_nodes1 = np.zeros(m,dtype=int)  
		end_nodes1 = np.zeros(m,dtype=int)  
		capacities1 = np.zeros(m,dtype=int)  
		unit_costs1 = np.zeros(m,dtype=int)  
		for z in range(m):  
			st = fileIn.readline()  
			u, v, i, f = (int(s) for s in st.split())  
			start_nodes1[z] = u-1  
			end_nodes1[z] = v-1  
			capacities1[z] = f  
			unit_costs1[z] = i

		# Define an array of supplies at each node.

		supplies1 = np.zeros(n,dtype=int)  
		for i in range(k):  
			st = fileIn.readline()  
			u, p = (int(s) for s in st.split())  
			supplies1[u-1] = p  
		for i in range(l):  
			st = fileIn.readline()  
			u, p = (int(s) for s in st.split())  
			supplies1[u-1] = -p  
  
		start_nodes = []  
		end_nodes = []  
		capacities = []  
		unit_costs = []  
		supplies = []  
		for i in start_nodes1:  
			start_nodes.append(i)  
		for i in end_nodes1:  
			end_nodes.append(i)  
		for i in capacities1:  
			capacities.append(i)  
		for i in unit_costs1:  
			unit_costs.append(i)  
		for i in supplies1:  
			supplies.append(i)  
  
  
		# Instantiate a SimpleMinCostFlow solver.  
		min_cost_flow = pywrapgraph.SimpleMinCostFlow()

		# Add each arc.  
		for i in range(0, len(start_nodes)):  
			min_cost_flow.AddArcWithCapacityAndUnitCost(start_nodes[i], end_nodes[i],capacities[i], unit_costs[i])  
		# Add node supplies.

		for i in range(0, len(supplies)):  
			min_cost_flow.SetNodeSupply(i, supplies[i])

		# Find the minimum cost flow between node 0 and node 4.  
		if min_cost_flow.SolveMaxFlowWithMinCost() == min_cost_flow.OPTIMAL:  
			print(min_cost_flow.OptimalCost())  
		else:  
			print('There was an issue with the min cost flow input.')

if __name__ == '__main__':  
	main()  
```

Original writeup
(https://github.com/AMACB/HSCTF-2020-writeups/blob/master/TrafficLightsA.md).