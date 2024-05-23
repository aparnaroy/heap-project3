# Project 3 - Heap Exploits

Here are 3 heap problems, the first is Mom's Spaghetti.  It is the one I want everyone to know inside and out.

Here's the baseline:

`tc->chunk2->chunk1->null`

Then you edit chunk2 (Use After Free)

So now it its:

`tc->chunk2->TARGET`

Now malloc twice and edit PAYLOAD into TARGET


## Level 1

Level 1 is glibc 2.31, use after free

## Level 2

Level 2 is glibc 2.32, use after free (singly linked lists are "encrypted")

## Level 3

Level 3 is glibc 2.32, only double free (Try house of botcake)

ipython3 lvl#.py
