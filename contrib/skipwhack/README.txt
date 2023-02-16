skipwhack: a tool to create skiplist-style files.

This is really simple, it takes a single argument, a directory name,
and will crash if not given it.

You can run multiple skipwhacks with the same directory and they will lock
against each other.

Running:
```
make
./skipwhack /path/to/dir
```

Output will be something like:

run file foo/data-61
Repacked foo/data-61 from 20324224 to 17577728
run file foo/data-0
Repacked foo/data-0 from 12199680 to 3322496
run file foo/data-57
Repacked foo/data-57 from 33393792 to 6905344
run file foo/data-17
run file foo/data-61
Repacked foo/data-61 from 43134592 to 10617856
run file foo/data-36


If you ever kill a process part way throug, a later skipwhack might see a
file where the header didn't commit and output:

WRONG LENGTH foo/data-18: 8CF880 9B1780

After which it will truncate the file to the previous "good" data and keep going.

This SHOULD recreate the data patterns of a twoskip database being appended to and occasionally repacked.  It does a full document scan on every open, which is NOT the same as real twoskip, so you won't quite get the read access patterns of a real twoskip - that can be added later if needed.
