/************************************************************************
 * Strathclyde Planning Group,
 * Department of Computer and Information Sciences,
 * University of Strathclyde, Glasgow, UK
 * http://planning.cis.strath.ac.uk/
 *
 * Copyright 2007, Keith Halsey
 * Copyright 2008, Andrew Coles and Amanda Smith
 *
 * (Questions/bug reports now to be sent to Andrew Coles)
 *
 * This file is part of JavaFF.
 *
 * JavaFF is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * JavaFF is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with JavaFF.  If not, see <http://www.gnu.org/licenses/>.
 *
* Edited by Daniel Crouch, Nov 2019
 ************************************************************************/

package javaff.search;

import javaff.planning.State;
import javaff.planning.Filter;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.LinkedList;
import java.util.Comparator;
import java.math.BigDecimal;

import java.util.Hashtable;
import java.util.Iterator;
import java.util.HashSet;


public class HillClimbingSearch extends Search
{

	protected Hashtable closed;
	protected LinkedList open;
	protected Filter filter = null;
	protected SuccessorSelector selector = null;
	protected int maxDepth = 10000;

	public HillClimbingSearch(State s)
	{
		this(s, new HValueComparator());
	}


	public HillClimbingSearch(State s, Comparator c)
	{
		super(s);
		setComparator(c);

		closed = new Hashtable();
		open = new LinkedList();
	}


	public void setFilter(Filter f)
	{
		filter = f;
	}

	public void setSelector(SuccessorSelector s)
	{
		selector = s;
	}

	public State removeNext()
	{
		return (State) ((LinkedList) open).removeFirst();
	}

	public void setMaxDepth(int d)
	{
		maxDepth = d;
	}


	public boolean needToVisit(State s) {
		Integer Shash = new Integer(s.hashCode()); // compute hash for state
		State D = (State) closed.get(Shash); // see if its on the closed list

		if (closed.containsKey(Shash) && D.equals(s)) return false;  // if it is return false

		closed.put(Shash, s); // otherwise put it on
		return true; // and return true
	}


	public State search()
	{
		// check if initial state is a goal, if not set to first state
		if (start.goalReached())
		{
			return start;
		}
		needToVisit(start); // dummy call (adds start to the list of 'closed' states so we don't visit it again
		open.add(start); // add it to the open list

		// keep track of search depth
		int depth = 0;
		javaff.JavaFF.infoOutput.println("Running HillClimbingSearch with max depth: " + maxDepth);

		// whilst still states to consider and depth not exceeded
		while (!open.isEmpty()  && depth < maxDepth) // whilst still states to consider
		{
			// Consider open states
			State s = removeNext(); // get the next one
			Set successors = s.getNextStates(filter.getActions(s)); // and find its neighbourhood

			// iterate through successors
			Iterator succItr = successors.iterator();
			while (succItr.hasNext())
			{
				State succ = (State) succItr.next(); // next successor

				if (needToVisit(succ))
				{
					// if we've found a goal state - return it as the solution
					if (succ.goalReached())
					{
						javaff.JavaFF.infoOutput.println("Goal found with state: " + succ);
						return succ;
					}
				}

			}

			// clear the open list
			open = new LinkedList();

			// and add selected next state to open list
			if (!successors.isEmpty())
			{
				// choose from next successors and replace in open list
				State selectedState = selector.choose(successors);
				open.add(selectedState); // add chosen successor to open list
			}

			// increase depth
			depth ++;

		}

		return null;
	}
}
