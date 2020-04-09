#!/usr/bin/env python3

# Main Ares module to be called on start-up. Alias for console.py
#
# Author: Daniel Crouch
# Date created: March 2020


from console import Console

if __name__ == '__main__':
    console = Console().cmdloop()
