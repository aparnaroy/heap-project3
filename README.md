# Project 3 - Heap Exploits

Here are 3 heap problems, the first is Mom's Spaghetti.  It is the one I want everyone to know inside and out.

Here's the baseline:

`tcache: chunk2->chunk1->null`

Then you edit chunk2 (Use After Free)

So now it its:

`tcache: chunk2->TARGET`

Now malloc twice and edit PAYLOAD into TARGET


## Level 1

Level 1 is glibc 2.31: Use After Free

## Level 2

Level 2 is glibc 2.32: Use After Free (but singly linked lists like tcache are "encrypted")

## Level 3

Level 3 is glibc 2.32: only Double Free (try House of Botcake)


## Running the Exploits

To run the exploit scripts, do the following (replacing `#` with the level number the exploit is for):

`ipython3 lvl#.py`
