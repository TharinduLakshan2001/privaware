#!/usr/bin/env python3
import time

def display_cat():
    cat_art = r"""
    /\_/\    
   ( o.o )  
    > ^ <
    """
    # Alternative dot-style cat
    dot_cat = r"""
    ·╭─────╮·
    │  ·  ·  │
    │   _    │
    ╰─(   )─╯
       \_/
    """
    
    print("\033[1;36m")  # Cyan color
    print(dot_cat)
    print("\033[0m")     # Reset color

if __name__ == "__main__":
    display_cat()
