# Automated Recon and Exploit Software (ARES) 
Automated penetration testing tool for Ubuntu Linux, designed as an extension to the Metasploit Framework. Applies a Metric-FF AI Planner to generate potential attack vectors automatically for the user. 

## Prerequisites
[Python 3.x](https://www.python.org/downloads/)

[Metasploit Framework](https://metasploit.help.rapid7.com/docs/installing-the-metasploit-framework)

[Nessus Essentials Vulnerability Scanner](https://www.tenable.com/products/nessus/nessus-essentials)

[PostgreSQL](https://www.postgresql.org)

Optional:

[PgAmin4](https://www.pgadmin.org/download/)

Install depdendancies:

```
python3 setup.py install
```

## Configuration

```MSF_LHOST```: static ip of host machine 

```NESSUS_USERNAME```: nessus account username 

```NESSUS_PASSWORD```: nessus account password

```POSTGRES_USER```: postgress username

```POSTGRES_PASSWORD```: postgess password

```POSTGRES_DB_NAME```: postgress database name 

## Usage

### Starting ARES software

You can start the application with ```./ares.py``` from the project directory. 

Type ```help``` to return instructions, or ```help method_name``` for usage and options.

### Commands

Setup: Initialise plugins as sub-processes and create the workspace environment. The process can take between 15-30 seconds to load as indicated by the loading prompt:
```python
>>> setup
```

Scan: Runs a selection of scans against an IP range of specific target:
```python
>>> scan hosts "ip range"
```
```python
>>> scan port "target name"
```
```python
>>> scan full "target name"3
```

Target: Creates a Target object model of a host at a given IP address and appends it to config.TARGETS. Target names must be unique:
>>> target "target name" "ip range"

Show: Displays target attributes to the console including IP addresses, accesses levels and detected vulnerabilities:
>>> show targets
>>> show target "target name"

Import: Allows the user to skip the scanning stage and import a scan report directlyfrom a CSV file into a target modal:
>>> import port "target name"
>>> import full "target name"

Metasploit: Opens an embedded Metasploit console beginning at the top directory. When active the user prompt will change to msf >>>. To exit back to the Ares console type cexit:
>>> msfmsf 
>>> cexit

Plan: Call the AI planner to generate a new attack vector:
>>> plan 

Exploit: Execute an exploit against a specified target, for example:
>>> exploit cve-2008-4250 "target name"

Shell: Execute a single-line shell command directly from the console command-line, for example:
>>> shell ls -la

Exit: Safely shut down the application
>>> exit (or>>> q)

Test: Run a number of pre-scripted unit tests directly, returns the time elapsed, errortracebacks and success status:
>>> test [1-7]

