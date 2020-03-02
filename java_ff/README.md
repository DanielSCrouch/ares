
## Extended Guide for Command Line shell scripts

Three scripts are provided as standard to compile and run JavaFF:

- `./build.sh` will build JavaFF for you
- `./run.sh <your-domain.pddl> <your-problem.pddl>` will run the built JavaFF on your domain and problem file (this will not work unless you've built first) (and optionally piping the output plan into a file)
- `benchmark_tests.sh` - A script for executing all of the PDDL benchmark domains, depots, driverlog and rovers. It should spit out the results we will be using to rank your implementations

`build.sh` and `benchmark_tests.sh` can be run on the command line simply by typing respectively

```bash
<your-javaff-repo-location>/build.sh
```
```bash
<your-javaff-repo-location>/benchmark_tests.sh
```

The `run.sh` script which can be (and should be) used to run your implementation of JavaFF should be executed like this

```bash
<your-javaff-repo-location>/run.sh <your-domain-location> <your-problem-location>
```

To get just the plan in a separate file, you can use `run.sh` like this

```bash
<your-javaff-repo-location>/run.sh <your-domain-location> <your-problem-location> <name-of-output-file>
```

for example **if I'm in my JavaFF folder** with a terminal already open I can run

```bash
./run.sh ./pddl/depots/domain.pddl ./pddl/depots/instances/instance-1.pddl
```
(This will run the first instance of the depots domain).

If I also want to save my plan to a file I could write

```bash
./run.sh ./pddl/depots/domain.pddl ./pddl/depots/instances/instance-1.pddl resulting_plan.txt
```

**Every time you make a change to your Java Code you will need to use the build script again before running**

## Useful Resources
- [The Planning Wiki](https://www.planning.wiki/) - The planning wiki has useful resources on writing PDDL (If you want a fun side project, fork and commit a page about JavaFF to the Planning Wiki - not worth any credit, but would be a great help)
