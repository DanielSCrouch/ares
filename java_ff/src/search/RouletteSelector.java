//
//
//  JavaFF
//
//  Created by Andrew Coles on Thu Jan 31 2008.
//

package javaff.search;

import javaff.planning.State;
import java.util.Iterator;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Enumeration;
import java.math.BigDecimal;
import java.math.RoundingMode;

public class RouletteSelector implements SuccessorSelector
{

	private static RouletteSelector ss = null;

	public static RouletteSelector getInstance()
	{
		if (ss == null)
			ss = new RouletteSelector(); // Singleton, as in NullFilter
		return ss;
	}

	public State choose(Set toChooseFrom)
	{
		if (toChooseFrom.isEmpty())
		{
			return null;
		}

		// check through states and store fitness score in dictionary
		HashMap fitnessMeasure = new HashMap();

		//Calculate the fitness values and their sum
		double sum = 0;
		Iterator itr = toChooseFrom.iterator();
		while (itr.hasNext())
		{
			State curr = (State) itr.next();
			double fitness = (BigDecimal.valueOf(1)).divide(curr.getHValue(), 5, RoundingMode.FLOOR).doubleValue();
			sum = sum + fitness;
			fitnessMeasure.put(curr, fitness);
		}

		// generate the random r value
		double r = javaff.JavaFF.generator.nextDouble() * sum;

		// iterate through fitness measures to find the one
		double fitnessSum = 0; // store cumulative fitness sum
		State chosenState = null;
		Iterator states = fitnessMeasure.keySet().iterator();

		while (states.hasNext())
		{
			State state = (State) states.next();
			double fitness = (double) fitnessMeasure.get(state);

			if (r >= fitnessSum && r <= (fitnessSum + fitness))
			{
				chosenState = state;
			}

			fitnessSum = fitnessSum + fitness;
		}

		return chosenState;

	};

};
