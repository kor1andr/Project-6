Name: Megan Garrett
Date: 11/23/2025
Environment: VS Code, Linux
Version Control: GitHub (https://github.com/kor1andr/Project-6)
- - - - - - - - - -
[AI] GPT 4.1
    [Prompts]
    - How should I structure the frame table and page table for each process in this program?
    - How can I block a worker process until its page fault is resolved?
    - Why am I getting the following errors/warnings when compiling?
    - Why are the memory resources not updating?
[Summary]
    Found to be very useful, unfortunately... I'm not a fan of the increasing over-reliance on generative AI and
    do not feel it should be a used as a replacement, as it so often is pushed to be in professional settings--but
    rather an aid. Still, it's been some years since I have worked with C/C++, so it has been especially useful in
    helping me refresh quickly and reducing testing/debug time.
    I am finding that output is not reflecting any memory resource usage. I believe this is because the message exchange
    is not correctly synching. The worker waits for a reply to its memory request, but OSS never sends one so nothing happens.
    I spent significant time trying to troubleshoot and fix this, but kept coming away with a bigger mess than when I started...
    Sorry!
- - - - - - - - - -
[How to Compile]
    - In the terminal, type 'make'
[How to Run]
After compiling:
    1) For detailed instructions and help:
        ./oss -h

    2) Run with default parameters:
        ./oss
        - This will launch 5 workers, up to 2 at a time, each for 3 simulated seconds, with 0.1 seconds between launches.

    [OR]

    3) Input your own command-line arguments to run:
        -n <number>     : Total number of workers to launch
        -s <number>     : Max number of workers to run simultaneously
        -t <float>      : Max simulated time for each worker (seconds, can be fractional)
        -i <float>      : Min time interval between worker launches (seconds, can be fractional)
        -f <filename>   : Log file for oss output
        
        Example:
            ./oss  -n 3    -s 1    -t 2.5  -i 0.2   -f log.txt
            - This will launch 3 workers, up to 1 at a time, each for up to 2.5 seconds, with 0.2 seconds between launches.

    4)  OSS will create and manage worker processes using shared memory for the system clock and a message queue for communication.
        Workers will randomly request memory access (read/write) and OSS handles paging and page faults.
        OSS will print and log the resource table and process table every 0.5 simulated seconds.
        OSS will clean up all shared memory/message queues and terminate after 60 real seconds or if interrupted with CTRL+C.

    5)  OSS output will print to both the screen and in the log file.
        Worker output will only appear on the screen.
