Name: Megan Garrett
Date: 11/23/2025
Environment: VS Code, Linux
Version Control: GitHub 
- - - - - - - - - -
[AI] GPT 4.1
    [Prompts]
    - 
[Summary]
    Found to be very useful, unfortunately... I'm not a fan of the increasing over-reliance on generative AI and
    do not feel it should be a used as a replacement, as it so often is pushed to be in professional settings--but
    rather an aid. Still, it's been some years since I have worked with C/C++, so it has been especially useful in
    helping me refresh quickly and reducing testing/debug time.
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
    4)  OSS will create and manage worker processes using shared memory for the system clock and message queues.
        Workers will randomly request or release resources following deadlock prevention rules (resource ordering).
        OSS will print and log the resource table and process table every 0.5 simulated seconds.
        OSS will clean up all resources and terminate after 60 real seconds or if interrupted with CTRL+C.
    5)  OSS output will print to both the screen and in the log file.
        Worker output will only appear on the screen.
    6)  All shared memory and message queues are removed automatically when OSS terminates.
