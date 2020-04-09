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

### Starting ARES software

