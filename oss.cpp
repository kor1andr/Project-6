#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>      // pid_t
#include <sys/wait.h>       // waitpid(), WNOHANG
#include <unistd.h>         // fork(), getpid(), getppid(), getopt()
#include <sys/ipc.h>        // IPC_CREAT, IPC_PRIVATE, IPC_RMID
#include <sys/shm.h>        // shmget(), shmat(), shmdt(), shmctl()
#include <sys/msg.h>        // msgget(), msgsnd(), msgrcv()
#include <signal.h>         // signal(), SIGINT, SIGALRM, sig_atomic_t
#include <fstream>          // std::ofstream
#include <vector>           // std::vector
#include <algorithm>        // std::sort
#include "stdio.h"          // snprintf()
#include "stdarg.h"         // va_list, va_start, va_end
#include <errno.h>          // debugging

// Print no more than 10k lines to a file
int lfprintf(FILE *stream,const char *format, ... ) {
    static int lineCount = 0;
    lineCount++;
    if (lineCount > 10000)
        return 1;
    va_list args;
    va_start(args, format);
    vfprintf(stream,format, args);
    va_end(args);
    return 0;
}

#define MAX_PROCS 18                // Max number of worker processes
#define BASE_QUANTUM_NS 10000000    // Base time quantum for scheduler (10 ms in nanoseconds)
// PAGING
#define PAGE_SIZE 1024
#define PROCESS_PAGES 16
#define SYSTEM_FRAMES 64

// SIMULATED CLOCK
struct SimClock {
    unsigned int seconds;           // unsigned int for only non-negative values
    unsigned int nanoseconds;
};

// PAGE TABLE ENTRY
struct PageTableEntry {
    int frame;      // frame number where page is stored (-1 if not in memory)
    bool valid;     // valid bit: true = page is in memory, false = page not in memory
};

// PROCESS CONTROL BLOCK
struct PCB {
    int occupied;                   // flag to indicate if entry currently in use; 1 = occupied, 0 = free
    pid_t pid;                      // stores PID of child process
    unsigned int startSeconds;      // time when process started
    unsigned int startNanoseconds;
    int messagesSent;               // # of messages sent to process by OSS
    // Scheduler Variables
    int serviceTimeSeconds;         // total simulated time allocated to process
    int serviceTimeNano;
    unsigned int eventWaitSec;      // simluated time at which process will become unblocked if waiting for an event
    unsigned int eventWaitNano;
    int blocked;                    // flag; 1 = blocked, 0 = ready
    unsigned int totalCpuTimeSec;   // total CPU time used by process
    unsigned int totalCpuTimeNano;
    unsigned int totalSysTimeSec;   // total time in system from creation to termination
    unsigned int totalSysTimeNano;
    PageTableEntry pageTable[PROCESS_PAGES];    // page table with 16 entries (pages 0-15)
};

// FRAME TABLE ENTRY
struct Frame {
    bool occupied;      // is frame in use
    bool dirty;         // has been modified since loaded
    int process;        // PID of owning process
    int page;           // page number within owning process
    unsigned int loadedTimeSec;     // time when page was loaded into frame
    unsigned int loadedTimeNano;
};

// MESSAGE QUEUE BUFFER
struct MsgBuf {
    long mtype;
    int status;         // 1 = running, 0 = wants to terminate
    int quantum;        // store the time quantum assigned to a worker processes
    int address;        // memory address requested
    int rw;             // 0 = read, 1 = write
    int result;         // used by worker to tell OSS how much of quantum it used
                            // 0 = denied, 1 = granted, 2 = page fault
};

/* flag to indicate termination signal received
    - [volatile]: tells compiler the terminateFlag value may change at any time, so do not cache its value
    - [sig_atomic_t]: int type to guarantees read/write operations are atomic
*/
volatile sig_atomic_t terminateFlag = 0;
// SIGNAL HANDLERS for graceful termination (release resources)
void handle_sigint(int) { terminateFlag = 1; }          // handle_sigint(): sets terminateFlag to 1 when SIGINT received
void handle_sigalrm(int) { terminateFlag = 1; }         // handle_sigalrm(): sets terminateFlag to 1 when SIGALRM received

// [DEBUG] Add a global flag
volatile sig_atomic_t msgrcvTimeout = 0;

// [DEBUG] Signal handler for alarm
void handle_msg_timeout(int) { msgrcvTimeout = 1; }

/* STATISTICS-BASED SCHEDULING ALGORITHM
    - [minRatio]: stores min ratio found so far; initialized to large value to ensure any valid ratio will be smaller
    - [selected]: index of chosen process in process table; initialized to -1 (no process selected)
    - Loops through process table entries
        - For each occupied (active) + unblocked (ready to run) process:
            - Calculate [sysTime], total time process has been in system (nowSec/Nano - startSec/Nano)
            - Calculate [cpuTime], total sim CPU time used by process (serviceTimeSec + serviceTimeNano / 1e9 to convert to seconds)
        - minRatio and selected updated whenever a new min ratio is found
            - If two processes have same ratio, select one with lower PID
        - Returns index of selected process, or -1 if none found
*/
int selectNextProcess(PCB processTable[], int maxProcs, unsigned int nowSec, unsigned int nowNano) {
    double minRatio = 1e9;
    int selected = -1;
    for (int i = 0; i < maxProcs; ++i) {
        if (processTable[i].occupied && !processTable[i].blocked) {
            // Calculate total time in system
            unsigned int sysSec = nowSec - processTable[i].startSeconds;
            int sysNano = nowNano - processTable[i].startNanoseconds;
            if (sysNano < 0) { sysSec -= 1; sysNano += 1000000000; }
            double sysTime = sysSec + sysNano / 1e9;
            double cpuTime = processTable[i].serviceTimeSeconds + processTable[i].serviceTimeNano / 1e9;
            double ratio = (sysTime > 0) ? (cpuTime / sysTime) : 0.0;
            if (ratio < minRatio || (ratio == minRatio && processTable[i].pid < processTable[selected].pid)) {
                minRatio = ratio;
                selected = i;
            }
        }
    }
    return selected;
}

// MAIN
int main(int argc, char* argv[]) {
    // DEFAULT VALUES for cmd line args
    int numberOfUsers = 5;          // # of workers to launch
    int simul = 2;                  // max # of simultaneous workers
    float timeLimit = 3.0f;         // time limit for each worker (seconds)
    float interval = 0.1f;          // min interval between worker launches (seconds)
    /* Support fractional values in -t:
        - Split timeLimit into seconds and nanoseconds
        - [maxSec]: stores integer # of seconds (e.g. 7 from 7.3)  
        - [maxNano]: stores fractional part converted to nanoseconds (e.g. 0.3 * 1,000,000,000 = 300,000,000 from 7.3)
    */
    int maxSec = (int)timeLimit;
    int maxNano = (int)((timeLimit - maxSec) * 1000000000);
    std::string logfile = "oss.log";
    int opt;                        // variable to hold opt character returned with getopt()

    // PARSE CMD LINE OPTIONS: getopt()
    while ((opt = getopt(argc, argv, "hn:s:t:i:f:")) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "Usage: " << argv[0] << " [-h] [-n proc] [-s simul] [-t timeLimit] [-i interval] [-f logfile]" << std::endl;
                std::cout << "  -h:             Help\n";
                std::cout << "  -n proc:        Number of total workers to launch\n";
                std::cout << "  -s simul:       Max number of simultaneous workers\n";
                std::cout << "  -t timelimitForChildren:            Amount of SIMULATED time before terminated (float, seconds)\n";
                std::cout << "  -i  intervalsInMsToLaunchChildren:  Min interval between launches (float, seconds)\n";
                return 0;
            case 'n':
                // [std::atoi]: convert arg to int and store in respective variable
                numberOfUsers = std::atoi(optarg);
                break;
            case 's':
                simul = std::atoi(optarg);
                break;
            case 't':
                timeLimit = std::atof(optarg);
                break;
            case 'i':
                interval = std::atof(optarg);
                break;
            case 'f':
                logfile = optarg;
                break;
            default:
                std::cerr << "[ERROR] Invalid option. Use -h for help.\n";
                return 1;
        }
    }

    // Validate cmd line args
    if (numberOfUsers <= 0 || simul <= 0 || timeLimit <= 0.0f || interval < 0.0f) {
        std::cerr << "[ERROR] Input must be non-negative values.\n";
        return 1;
    }

    // Log File Error Check
    FILE* logf = fopen(logfile.c_str(), "w");
    if (!logf) {
        std::cerr << "[ERROR] Could not open log file: " << std::endl;
        return 1;
    }

    std::cout << "OSS starting... PID: " << getpid() << ", PPID: " << getppid() << std::endl;
    lfprintf(logf, "OSS starting... PID: %d, PPID: %d\n", getpid(), getppid());
    /*      DEBUG PRINT:
    std::cout << "Called with:" << std::endl;
    std::cout << "-n: " << numberOfUsers << std::endl;
    std::cout << "-s: " << simul << std::endl;
    std::cout << "-t: " << timeLimit << std::endl;
    std::cout << "-i: " << interval << std::endl;
    */

    // SIGNAL HANDLERS
    signal(SIGINT, handle_sigint);
    signal(SIGALRM, handle_sigalrm);
    alarm(5);          // set timer to send SIGALRM singal after 5 real time seconds    

    // SHARED MEMORY
        // [shmget()]: request shm segment == size of SimClock struct
        // [IPC_PRIVATE]: create new, unique shared memory segment
        // [IPC_CREAT]: create segment if it doesn't already exist
        // [0666]: read and write permissions for all users
    int shm_id = shmget(IPC_PRIVATE, sizeof(SimClock), IPC_CREAT | 0666);
    
    // shmget() error check
    if (shm_id < 0) {
        std::cerr << "[ERROR] shmget failed." << std::endl;
        return 1;
    }

    // SimClock* = pointer to SimClock struct to access shared memory as a clock
        // [shmat()]: attach shm segment to process's address space so it can be accessed
        // [nullptr, 0]: let system choose address to attach segment, default flags
    SimClock* clock = (SimClock*) shmat(shm_id, nullptr, 0);
    // If shmat() fails, remove the shared memory segment to prevent memory leaks
    if (clock == (void*) -1) {
        std::cerr << "[ERROR] shmat failed." << std::endl;
        lfprintf(logf, "OSS: [ERROR] shmat failed." );
        shmctl(shm_id, IPC_RMID, nullptr);          // IPC_RMID = remove shared memory segment
        return 1;
    }
    // Initialize simulated clock to 0, so it begins at known state
    clock->seconds = 0;
    clock->nanoseconds = 0;

    // MESSAGE QUEUE
        // [ftok()]: generate unique key for message queue based on file path and id
        // [msgget()]: create message queue for IPC between oss and workers
        // [IPC_CREAT]: create queue if it doesn't already exist
        // [0666]: read and write permissions for all users
    key_t msg_key = ftok(argv[0], 65);
    int msqid = msgget(msg_key, IPC_CREAT | 0666);
    if (msqid < 0) {
        std::cerr << "[ERROR] msgget failed." << std::endl;
        lfprintf(logf, "OSS: [ERROR] msgget failed." );
        shmdt(clock);
        shmctl(shm_id, IPC_RMID, nullptr);
        return 1;
    }
    
    // VARIABLES
    PCB processTable[MAX_PROCS] = {};                           // [processTable]: array to hold up to MAX_PROCS instances of the PCB struct
    int running = 0;                                            // [running]: current # of active child processes       
    int launched = 0;                                           // [launched]: total # of workers launched so far
    int totalMessages = 0;                                      // [totalMessages]: total # of messages received from workers
    unsigned int lastLaunchSec = 0, lastLaunchNano = 0;         // [lastLaunchSec/Nano]: track time last worker was launched
    unsigned int lastTablePrintSec = 0, lastTablePrintNano = 0; // [lastTablePrintSec/Nano]: track time last process table was printed
    unsigned int totalWorkerSeconds = 0, totalWorkerNanoseconds = 0; // [totalWorkerSeconds/Nanoseconds]: track total CPU time used by all workers
    unsigned long long totalWaitTime = 0;                       // nanoseconds
    unsigned long long totalBlockedTime = 0;                    // nanoseconds
    unsigned long long totalIdleTime = 0;                       // nanoseconds
    unsigned int totalBlockedEvents = 0;                        // count of times a process was blocked
    Frame frameTable[SYSTEM_FRAMES] = {};                       // [frameTable]: array to hold SYSTEM_FRAMES instances of Frame struct
    std::vector<int> fifoQueue;                                 // FIFO queue to track frame loading order for page replacement
    unsigned int lastMemoryPrintSec = 0;
    unsigned int lastMemoryPrintNano = 0;
    int totalPageFaults = 0;
    int totalReads = 0;
    int totalWrites = 0;

    srand(time(NULL));
    // int nextChild = 0;                                       // [nextChild]: index of next child process to launch in process table

    // Vector to manage blocked processes
    std::vector<int> blockedQueue;

    /* INITIALIZE RESOURCE TABLE
        - Iterate through each resource class (R0-R9)
        - Set totalInstances and availableInstances to INSTANCES_PER_RESOURCE (5), so every resource clas starts with all 5 instances available for allocation
        - Iterate through each possible process (0 to MAX_PROCS-1)
            - Set # of instances of the current resource class allocated to that process to 0, so no resources are allocated at start
    for (int i = 0; i < RESOURCE_CLASSES; ++i) {
        resourceTable[i].totalInstances = INSTANCES_PER_RESOURCE;
        resourceTable[i].availableInstances = INSTANCES_PER_RESOURCE;
        for (int j = 0; j < MAX_PROCS; ++j)
            resourceTable[i].allocated[j] = 0;
    }
    */

    // MAIN LOOP
    while ((launched < numberOfUsers || running > 0) && !terminateFlag) {
        // Check for terminated child processes (NON-BLOCKING)
        int status = 0;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {     // [waitpid] + [WNOHANG]: non-blocking check for finished child processes
            running--;
            // Find and update PCB for terminated child
            for (int i = 0; i < MAX_PROCS; i++) {
                if (processTable[i].occupied && processTable[i].pid == pid) {
                    unsigned int startSec = processTable[i].startSeconds;
                    unsigned int startNano = processTable[i].startNanoseconds;
                    unsigned int endSec = clock->seconds;
                    unsigned int endNano = clock->nanoseconds;
                    unsigned int runSec = endSec - startSec;
                    int runNano = endNano - startNano;

                    if (runNano < 0) {
                        runSec -= 1;
                        runNano += 1000000000;
                    }
                    totalWorkerSeconds += runSec;
                    totalWorkerNanoseconds += runNano;

                    // Mark PCB as free (reuse old entries)
                    processTable[i].occupied = 0;
                    processTable[i].pid = 0;
                    processTable[i].startSeconds = 0;
                    processTable[i].startNanoseconds = 0;
                    processTable[i].messagesSent = 0;
                    processTable[i].serviceTimeSeconds = 0;
                    processTable[i].serviceTimeNano = 0;
                    break;
                }
            }
        }
        // INCREMENT SIMULATED CLOCK
        // if running > 0, increment = 0.25 sec / running; else increment = 0.025 sec
        int increment = running > 0 ? (250000000 / running) : 250000000;
        clock->nanoseconds += increment;
        while (clock->nanoseconds >= 1000000000) {
            clock->seconds += 1;
            clock->nanoseconds -= 1000000000;
        }
        /* TRACK IDLE TIME + UTILIZATION
            - Check if any processes in the system are READY to run
                (i.e. loop through PT entries searching for PCB entry that is occupied AND NOT blocked)
                - If a matching entry is found, set anyReady flag to true and break loop
            - If no READY processes AND there are running processes, CPU is idle waiting for READY process
                - Incremenet [totalIdleTime] by [increment] var value 
        */
        bool anyReady = false;
        for (int i = 0; i < MAX_PROCS; ++i) {
            if (processTable[i].occupied && !processTable[i].blocked) {
                anyReady = true;
                break;
            }
        }
        if (!anyReady && running > 0) {
            totalIdleTime += increment;
        }

        /* BLOCKED QUEUE HANDLING
            - Iterate through each entry in process table to check if occupied (active) AND blocked
            - If both true, compare current sim clock time to process's eventWaitSec/Nano
            - If current time >= eventWait time, set blocked flag to 0 (ready) and log unblocking event
            - Increment sim clock by 2000 nanoseconds to simulate time taken to unblock process
            - Handle possible nanosecond overflow
        */
        for (int i = 0; i < MAX_PROCS; ++i) {
            if (processTable[i].occupied && processTable[i].blocked) {
                if  (clock->seconds > processTable[i].eventWaitSec ||
                    (clock->seconds == processTable[i].eventWaitSec && clock->nanoseconds >= processTable[i].eventWaitNano)) {
                        processTable[i].blocked = 0;
                        lfprintf(logf, "OSS: Unblocking proces PID %d at time %u:%u\n", processTable[i].pid, clock->seconds, clock->nanoseconds);
                        
                        clock->nanoseconds += 2000;
                        if (clock->nanoseconds >= 1000000000) {
                            clock->seconds += 1;
                            clock->nanoseconds -= 1000000000;
                        }
                }
            }
        }

        // PRINT PROCESS TABLE every 0.5 simulated seconds
        // Calculate elapsed time since last print in nanosec
        unsigned int elapsedNano = (clock->seconds - lastTablePrintSec) * 1000000000 + (clock->nanoseconds - lastTablePrintNano);
        if (elapsedNano >= 500000000) {
            std::cout << "OSS PID: " << getpid() << std::endl;
            lfprintf(logf, "OSS PID: %d\n", getpid());
            std::cout << "SysClokS: " << clock->seconds << std::endl;
            std::cout << "SysClockNano: " << clock->nanoseconds << std::endl;
            lfprintf(logf, "SysClockS: %u\n", clock->seconds);
            lfprintf(logf, "SysClockNano: %u\n", clock->nanoseconds);

            std::cout << "- - - Process Table - - -" << std::endl;
            std::cout << "Entry | Occupied | PID | StartS | StartN | MessagesSent" << std::endl;
            lfprintf(logf, "- - - Process Table - - -\n");
            lfprintf(logf, "Entry | Occupied | PID | StartS | StartN | MessagesSent\n");
            for (int i = 0; i < MAX_PROCS; i++) {
                std::cout << i << " | "
                          << processTable[i].occupied << " | "
                          << processTable[i].pid << " | "
                          << processTable[i].startSeconds << " | "
                          << processTable[i].startNanoseconds << " | "
                          << processTable[i].messagesSent << std::endl;
                lfprintf(logf, "%d | %d | %d | %u | %u | %d\n", i, processTable[i].occupied, processTable[i].pid, processTable[i].startSeconds, processTable[i].startNanoseconds, processTable[i].messagesSent);
            }

            //Print list of currently blocked processes
            std::cout << "Blocked Processes: [";
            lfprintf(logf, "Blocked Processes: [");
            bool firstBlocked = true;
            for (int i = 0; i < MAX_PROCS; i++) {
                if (processTable[i].occupied && processTable[i].blocked) {
                    if (!firstBlocked) {
                        std::cout << ", ";
                        lfprintf(logf, ", ");
                    }
                    std::cout << "PID " << processTable[i].pid << " (Entry " << i << ", Unblock at " << processTable[i].eventWaitSec << ":" << processTable[i].eventWaitNano << ")";
                    lfprintf(logf, "PID %d (Entry %d, Unblock at %u:%u)", processTable[i].pid, i, processTable[i].eventWaitSec, processTable[i].eventWaitNano);
                    firstBlocked = false;
                }
            }
            std::cout << "]" << std::endl;
            lfprintf(logf, "]\n");
            // End blocked process list

            // Update last print time to current clock time
            lastTablePrintSec = clock->seconds;
            lastTablePrintNano = clock->nanoseconds;

            // PRINT FRAME TABLE
            unsigned int elapsedMemNano = (clock->seconds - lastMemoryPrintSec) * 1000000000 + (clock->nanoseconds - lastMemoryPrintNano);
            if (elapsedMemNano >= 1000000000) {
            std::cout << "Current memory layout at time " << clock->seconds << ":" << clock->nanoseconds << std::endl;
            lfprintf(logf, "Current memory layout at time %u:%u\n", clock->seconds, clock->nanoseconds);
            std::cout << "Occupied DirtyBit Process Page" << std::endl;
            lfprintf(logf, "Occupied DirtyBit Process Page\n");
            for (int i = 0; i < SYSTEM_FRAMES; ++i) {
                std::cout << "Frame " << i << ": " << (frameTable[i].occupied ? "Yes" : "No") << " "
                << frameTable[i].dirty << " " << frameTable[i].process << " " << frameTable[i].page << std::endl;
                lfprintf(logf, "Frame %d: %s %d %d %d\n", i, frameTable[i].occupied ? "Yes" : "No", frameTable[i].dirty, frameTable[i].process, frameTable[i].page);
            }
            for (int p = 0; p < MAX_PROCS; ++p) {
                if (processTable[p].occupied) {
                    std::cout << "P" << p << " page table: [ ";
                    lfprintf(logf, "P%d page table: [ ", p);
                    for (int pg = 0; pg < PROCESS_PAGES; ++pg) {
                        std::cout << processTable[p].pageTable[pg].frame << " ";
                        lfprintf(logf, "%d ", processTable[p].pageTable[pg].frame);
                    }
                    std::cout << "]" << std::endl;
                    lfprintf(logf, "]\n");
                }
            }
        lastMemoryPrintSec = clock->seconds;
        lastMemoryPrintNano = clock->nanoseconds;
        }
    }

        // LAUNCH NEW CHILD WORKER PROCESSES

        /* SIMULTANEOUS RESTRICTION:
            - check if total # [launched] < desired # [numberOfUsers]
            - check if [running] < allowed limit [simul]
        */
        if (launched < numberOfUsers && running < simul) {
            // calculate amount of sim time passed since last worker launch
            unsigned int sinceLastLaunch = (clock->seconds - lastLaunchSec) * 1000000000 + (clock->nanoseconds - lastLaunchNano);
            if (sinceLastLaunch >= (unsigned int)(interval * 1e9)) {
                int pcbIndex = -1;
                for (int i = 0; i < MAX_PROCS; ++i) {
                    // loop through process table entries to find unoccupied slot
                    if (!processTable[i].occupied) { 
                        pcbIndex = i;
                        break;
                    }
                }
                // If available slot found in process table, oss to fork() then exec() off one worker to do its task
                if (pcbIndex != -1) {
                    /* Generate random time limit for worker between 1 and timeLimit
                        - [tsec]: assigned random int between 1 and maxSec (inclusive)
                            - if maxSec = 0, use 1 as upper bound to avoid % 0 error
                    */
                    int tSec = 1 + rand() % (maxSec == 0 ? 1 : maxSec);
                    int tNano;
                    if (maxNano > 0) {
                        // [tnano]: assigned random int between 0 and maxNano (exclusive)
                        tNano = rand() % maxNano;
                    } else {
                        // if maxNano ≤ 0, generate random int between 0 and 999,999,999 to ensure valid nanosec value
                        tNano = rand() % 1000000000;
                    }

                    pid_t cpid = fork();
                    if (cpid < 0) {
                        // fork() failed
                        std::cerr << "[ERROR] fork failed.\n";
                        lfprintf(logf, "OSS: [ERROR] fork failed.\n");
                    } else if (cpid == 0) {
                        // CHILD PROCESS
                        char secArg[16], nanoArg[16], shmIdArg[16], msqIdArg[16];   // arrays to store args' string equivalent, which will be passed to worker process
                        snprintf(secArg, sizeof(secArg), "%d", tSec);               // [snprintf]: convert calculated values and shm_id to strings
                        snprintf(nanoArg, sizeof(nanoArg), "%d", tNano);
                        snprintf(shmIdArg, sizeof(shmIdArg), "%d", shm_id);
                        snprintf(msqIdArg, sizeof(msqIdArg), "%d", msqid);

                        execlp("./worker", "worker", secArg, nanoArg, shmIdArg, msqIdArg, nullptr);   // [execlp]: replaces child process with worker executable
                        // if execlp() fails, print error and exit child process
                        std::cerr << "[ERROR] execlp failed.\n";
                        lfprintf(logf, "OSS: [ERROR] execlp failed.\n");
                        exit(1);
                    } else {
                        processTable[pcbIndex].occupied = 1;
                        processTable[pcbIndex].pid = cpid;
                        processTable[pcbIndex].startSeconds = clock->seconds;
                        processTable[pcbIndex].startNanoseconds = clock->nanoseconds;
                        processTable[pcbIndex].messagesSent = 0;
                        processTable[pcbIndex].serviceTimeSeconds = tSec;
                        processTable[pcbIndex].serviceTimeNano = tNano;
                        processTable[pcbIndex].eventWaitSec = 0;
                        processTable[pcbIndex].eventWaitNano = 0;
                        processTable[pcbIndex].blocked = 0;
                        processTable[pcbIndex].totalCpuTimeSec = 0;
                        processTable[pcbIndex].totalCpuTimeNano = 0;
                        processTable[pcbIndex].totalSysTimeSec = 0;
                        processTable[pcbIndex].totalSysTimeNano = 0;

                        running++;
                        launched++;
                        lastLaunchSec = clock->seconds;
                        lastLaunchNano = clock->nanoseconds;
                        std::cout << "Launched worker " << pcbIndex << " PID " << cpid << std::endl;
                        lfprintf(logf, "OSS: Launched worker %d PID %d\n", pcbIndex, cpid);
                    }
                }
            }
        }

        /* SCHEDULER
            - [selectNextProcess]: examines process table and selects next process to run based on scheduling algorithm; returns index of selected process or -1 if none found
            - [MsgBuf msg]: create message buffer to send to selected process
            - [mtype]: set to PID of selected process (so only that process receives the message); status = 1 (indicates process should continue running)
            - [msg.quantum]: assign base quantum to selected process
            - [msgsnd]: place message in message queue for selected process
            - [msg.result]: used by worker to tell OSS how much of quantum it used
            - increment messagesSent and totalMessages counters
            - [msgrcv]: wait for reply message from selected process (mtype = PID + 1000 to differentiate from messages sent to process)
            - if reply.status == 0, process is planning to terminate; this info is logged
        */
        // Log ready queue priorities/ratios
        std::cout << "OSS: Ready queue priorities [";
        lfprintf(logf, "OSS: Ready queue priorities [");
        bool first = true;
        for (int i = 0; i < MAX_PROCS; ++i) {
            if (processTable[i].occupied && !processTable[i].blocked) {
                unsigned int sysSec = clock->seconds - processTable[i].startSeconds;
                int sysNano = clock->nanoseconds - processTable[i].startNanoseconds;
                if (sysNano < 0) {
                    sysSec -= 1; sysNano += 1000000000;
                }
                double sysTime = sysSec + sysNano / 1e9;
                double cpuTime = processTable[i].serviceTimeSeconds + processTable[i].serviceTimeNano / 1e9;
                double ratio = (sysTime > 0) ? (cpuTime / sysTime) : 0.0;
                if (!first) {
                    std::cout << ",";
                    lfprintf(logf, ",");
                }
            std::cout << ratio;
            lfprintf(logf, "%.4f", ratio);
            first = false;
            }
        }
        
        std::cout << "]" << std::endl;
        lfprintf(logf, "]\n");

        int selected = selectNextProcess(processTable, MAX_PROCS, clock->seconds, clock->nanoseconds);
        if (selected != -1) {
            // Double-check process is still valid before sending message
            if (processTable[selected].occupied && processTable[selected].pid > 0) {
                // Track total wait time for selected process
                unsigned int waitSec = clock->seconds - processTable[selected].startSeconds;
                int waitNano = clock->nanoseconds - processTable[selected].startNanoseconds;
                if (waitNano < 0) {
                    waitSec -= 1;
                    waitNano += 1000000000;
                }
                totalWaitTime += waitSec * 1000000000ULL + waitNano;

                // Check if process is still alive before send
                if (kill(processTable[selected].pid, 0) == -1) {
                    // Process is dead, clean up PCB and skip further processing
                    processTable[selected].occupied = 0;
                    processTable[selected].pid = 0;
                    processTable[selected].blocked = 0;
                    std::cout << "OSS: Worker PID " << processTable[selected].pid << " is not alive before send. PCB cleaned up." << std::endl;
                    continue;
                }
                
                MsgBuf msg;
                msg.mtype = processTable[selected].pid;
                msg.status = 1;
                msg.quantum = BASE_QUANTUM_NS;
                msg.result = 0;
                msgsnd(msqid, &msg, sizeof(MsgBuf) - sizeof(long), 0);
                processTable[selected].messagesSent++;
                totalMessages++;
                std::cout << "Sending message to worker " << selected << " PID " << processTable[selected].pid << " at time " << clock->seconds << ":" << clock->nanoseconds << std::endl;
                lfprintf(logf, "OSS: Sending message to worker %d PID %d at time %u:%u\n", selected, processTable[selected].pid, clock->seconds, clock->nanoseconds);

                // Set up for non-blocking msgrcv
                MsgBuf reply;
                unsigned int startSec = clock->seconds;
                unsigned int startNano = clock->nanoseconds;
                const unsigned int timeout_ns = 2000000000; // 2 seconds in nanoseconds

                bool gotReply = false;
                while (!gotReply) {
                    if (terminateFlag) break;
                    ssize_t rcvResult = msgrcv(msqid, &reply, sizeof(MsgBuf) - sizeof(long), processTable[selected].pid + 1000, IPC_NOWAIT);
                    if (rcvResult != -1) {
                        gotReply = true;
                        break;
                    }
                    // Check for timeout (2 seconds simulated time)
                    unsigned int elapsedSec = clock->seconds - startSec;
                    int elapsedNano = clock->nanoseconds - startNano;
                    if (elapsedNano < 0) {
                        elapsedSec -= 1;
                        elapsedNano += 1000000000;
                    }
                    unsigned int elapsedTotal = elapsedSec * 1000000000 + elapsedNano;
                    if (elapsedTotal > timeout_ns) {
                        // Timeout: clean up PCB and skip further processing
                        processTable[selected].occupied = 0;
                        processTable[selected].pid = 0;
                        processTable[selected].blocked = 0;
                        std::cout << "OSS: Worker PID " << processTable[selected].pid << " did not respond in time. PCB cleaned up." << std::endl;
                        break;
                    }
                    // Optionally, yield or do a small busy-wait
                }
                if (!gotReply) continue; // Skip to next loop iteration if timeout

                // Now safe to update PCB and process reply
                int usedTime = abs(reply.result);
                clock->nanoseconds += usedTime;
                while (clock->nanoseconds >= 1000000000) {
                    clock->seconds += 1;
                    clock->nanoseconds -= 1000000000;
                }

                // Update PCB service time
                processTable[selected].serviceTimeNano += usedTime;
                while (processTable[selected].serviceTimeNano >= 1000000000) {
                    processTable[selected].serviceTimeSeconds += 1;
                    processTable[selected].serviceTimeNano -= 1000000000;
                }

                if (reply.result < 0) {
                    // Process terminated
                    lfprintf(logf, "OSS: Process PID %d terminated after using %d ns\n", processTable[selected].pid, usedTime);
                    // PCB cleanup is handled in the waitpid loop at the top of the main loop
                } else if (reply.status == 2) {
                    // Blocked
                    processTable[selected].blocked = 1;
                    processTable[selected].eventWaitSec = clock->seconds;
                    processTable[selected].eventWaitNano = clock->nanoseconds + 600000000;
                    if (processTable[selected].eventWaitNano >= 1000000000) {
                        processTable[selected].eventWaitSec += 1;
                        processTable[selected].eventWaitNano -= 1000000000;
                    }
                    lfprintf(logf, "OSS: Process PID %d blocked until %d:%d\n", processTable[selected].pid, processTable[selected].eventWaitSec, processTable[selected].eventWaitNano);
                    totalBlockedEvents++;
                    totalBlockedTime += 600000000;
                } else {
                    lfprintf(logf, "OSS: Process PID %d used full quantum\n", processTable[selected].pid);
                }
            }
        }

        if (msgrcvTimeout) {
            msgrcvTimeout = 0;
            continue;
        }

        /* MSG QUEUE TO HANDLE INCOMING RESOURCE REQUESTS FROM WORKER PROCESSES
        (allows oss to asynchronously handle resource requests, respond, and keep record of resource allocation)
            - [msg]: MsgBuf structure to store incoming message
            - [msgrcv]: called with [msqid]
                - [msqid]: pointer to [msg]
                    - [msg]: size of message
                    - msgtype = 0 (receive any type)
            - [IPC_NOWAIT]: non-blocking flag; if no message available, return immediately with -1
        */
        MsgBuf msg;
        ssize_t rcv = msgrcv(msqid, &msg, sizeof(MsgBuf) - sizeof(long), 0, IPC_NOWAIT);
        
        if (rcv != -1) {
        // Find which process sent request by matching PID
        int procIndex = -1;
        for (int i = 0; i < MAX_PROCS; ++i) {
            if (processTable[i].occupied && processTable[i].pid == msg.mtype) {
                procIndex = i;
                break;
            }
        }
        if (procIndex != -1) {
            // Extract requested address and read/write flag from message
            int address = msg.address;
            int rw = msg.rw;
            // Which page is being accessed
            int page = address / PAGE_SIZE;
            // COffset within page
            int offset = address % PAGE_SIZE;

            // Update read/write counters
            if (rw == 0) totalReads++;
            else totalWrites++;

            // Check if the requested page is already loaded in memory (valid bit)
            if (processTable[procIndex].pageTable[page].valid) {
                // Page is in memory: get frame index
                int frameIdx = processTable[procIndex].pageTable[page].frame;

                // If write, set dirty bit for the frame
                if (rw == 1) frameTable[frameIdx].dirty = true;

                // Log memory access
                std::cout   << "OSS: P" << procIndex << " " << (rw ? "write" : "read")
                            << " of address " << address << " at time "
                            << clock->seconds << ":" << clock->nanoseconds << std::endl;
                lfprintf(logf, "OSS: P%d %s of address %d at time %u:%u\n",
                        procIndex, rw ? "write" : "read", address, clock->seconds, clock->nanoseconds);
                
                // Increment clock by 100ns for memory access
                clock->nanoseconds += 100;
                if (clock->nanoseconds >= 1000000000) {
                    clock->seconds++;
                    clock->nanoseconds -= 1000000000;
                }

                // Send reply to worker: request granted (result = 1)
                MsgBuf reply;
                reply.mtype = processTable[procIndex].pid + 1000;
                reply.result = 1;
                msgsnd(msqid, &reply, sizeof(MsgBuf) - sizeof(long), 0);
            } else {
                // Page fault: requested page NOT in memory
                totalPageFaults++;
                std::cout   << "OSS: P" << procIndex << " page fault for address "
                            << address << " (page " << page << ")" << std::endl;
                lfprintf(logf, "OSS: P%d page fault for address %d (page %d)\n",
                        procIndex, address, page);

                // Find free frame or FIFO victim
                int frameIdx = -1;
                for (int i = 0; i < SYSTEM_FRAMES; ++i) {
                    if (!frameTable[i].occupied) {
                        frameIdx = i; break;
                    }
                }

                // If no free frame, use FIFO page replacement to evict oldest frame
                if (frameIdx == -1) {
                    // FIFO: remove the frame that was loaded first (front of fifoQueue)
                    frameIdx = fifoQueue.front();
                    fifoQueue.erase(fifoQueue.begin());
                    std::cout   << "OSS: Clearing frame " << frameIdx
                                << " and swapping in p" << procIndex << " page " << page << std::endl;
                    lfprintf(logf, "OSS: Clearing frame %d and swapping in p%d page %d\n",
                            frameIdx, procIndex, page);

                    // If the frame being evicted is dirty, add extra time to simulate writing back to disk
                    if (frameTable[frameIdx].dirty) {
                        std::cout   << "OSS: Dirty bit of frame " << frameIdx
                                    << " set, adding additional time to the clock" << std::endl;
                        lfprintf(logf, "OSS: Dirty bit of frame %d set, adding additional time to the clock\n", frameIdx);
                        clock->nanoseconds += 1000000; // 1ms extra
                        if (clock->nanoseconds >= 1000000000) {
                            clock->seconds++;
                            clock->nanoseconds -= 1000000000;
                        }
                    }
                    // Mark the evicted page as invalid in its process's page table
                    int oldProc = frameTable[frameIdx].process;
                    int oldPage = frameTable[frameIdx].page;
                    if (oldProc >= 0 && oldPage >= 0)
                        processTable[oldProc].pageTable[oldPage].valid = false;
                }

                // Load requested page into the chosen frame
                frameTable[frameIdx].occupied = true;
                frameTable[frameIdx].dirty = (rw == 1); // Set dirty if write
                frameTable[frameIdx].process = procIndex;
                frameTable[frameIdx].page = page;
                frameTable[frameIdx].loadedTimeSec = clock->seconds;
                frameTable[frameIdx].loadedTimeNano = clock->nanoseconds;
                processTable[procIndex].pageTable[page].frame = frameIdx;
                processTable[procIndex].pageTable[page].valid = true;
                fifoQueue.push_back(frameIdx); // Add frame to FIFO queue

                // Simulate disk I/O: block for 14ms
                clock->nanoseconds += 14000000;
                while (clock->nanoseconds >= 1000000000) {
                    clock->seconds++;
                    clock->nanoseconds -= 1000000000;
                }

                // Send reply to worker: page fault handled (result = 2)
                MsgBuf reply;
                reply.mtype = processTable[procIndex].pid + 1000;
                reply.result = 2;
                msgsnd(msqid, &reply, sizeof(MsgBuf) - sizeof(long), 0);
            }
        }
    }
} // END MAIN LOOP

    // If terminateFlag set, send SIGTERM to all active workers
    if (terminateFlag) {
        std::cout << "OSS: Termination signal received. Terminating all workers..." << std::endl;
        lfprintf(logf, "OSS: Termination signal received. Terminating all workers..." );
        for (int i = 0; i < MAX_PROCS; i++) {
            if (processTable[i].occupied) {
                kill(processTable[i].pid, SIGTERM);
            }
        }
        // Optionally, wait for children to exit
        while (waitpid(-1, nullptr, WNOHANG) > 0) {}
    }

    // Convert excess nanosec to seconds so value is < 1 billion
    totalWorkerSeconds += totalWorkerNanoseconds / 1000000000;
    totalWorkerNanoseconds = totalWorkerNanoseconds % 1000000000;

    // PRINT STATISTICS
    unsigned long long totalSimTime = clock->seconds * 1000000000ULL + clock->nanoseconds;
    unsigned long long totalCpuTime = totalWorkerSeconds * 1000000000ULL + totalWorkerNanoseconds;

    double avgWaitTime = (launched > 0) ? (double)totalWaitTime / launched / 1e6 : 0;       // milliseconds
    double avgBlockedTime = (totalBlockedEvents > 0) ? (double)totalBlockedTime / totalBlockedEvents / 1e6 : 0;
    double cpuUtilization = (totalSimTime > 0) ? ((double)totalCpuTime / totalSimTime) * 100.0 : 0.0;
    double avgIdleTime = (double)totalIdleTime / 1e6;

    std::cout << "----- STATISTICS -----" << std::endl;
    std::cout << "Average wait time per process: " << avgWaitTime << " ms" << std::endl;
    std::cout << "Average blocked time per event: " << avgBlockedTime << " ms" << std::endl;
    std::cout << "CPU Utilization: " << cpuUtilization << " %" << std::endl;
    std::cout << "Total idle time: " << avgIdleTime << " ms" << std::endl;

    lfprintf(logf, "----- STATISTICS -----\n");
    lfprintf(logf, "Average wait time per process: %.3f ms\n", avgWaitTime);
    lfprintf(logf, "Average blocked time per event: %.3f ms\n", avgBlockedTime);
    lfprintf(logf, "CPU Utilization: %.2f %%\n", cpuUtilization);
    lfprintf(logf, "Total CPU idle time: %.3f ms\n", avgIdleTime);
    
    // PRINT PAGING STATISTICS
    std::cout << "Total page faults: " << totalPageFaults << std::endl;
    std::cout << "Total reads: " << totalReads << std::endl;
    std::cout << "Total writes: " << totalWrites << std::endl;
    double pageFaultPercent = (totalReads + totalWrites > 0) ? (double)totalPageFaults / (totalReads + totalWrites) * 100.0 : 0.0;
    std::cout << "Page fault percentage: " << pageFaultPercent << "%" << std::endl;
    lfprintf(logf, "Total page faults: %d\n", totalPageFaults);
    lfprintf(logf, "Total reads: %d\n", totalReads);
    lfprintf(logf, "Total writes: %d\n", totalWrites);
    lfprintf(logf, "Page fault percentage: %.2f%%\n", pageFaultPercent);    
    
    // CLEANUP
    shmdt(clock);
    shmctl(shm_id, IPC_RMID, nullptr);
    msgctl(msqid, IPC_RMID, nullptr);

    std::cout << "OSS PID: " << getpid() << " Terminating" << std::endl;
    lfprintf(logf, "OSS PID: %d Terminating\n", getpid());

    std::cout << launched << " workers were launched and terminated." << std::endl;
    lfprintf(logf, "%d workers were launched and terminated.\n", launched);

    std::cout << "OSS sent a total of " << totalMessages << " messages to workers." << std::endl;
    lfprintf(logf, "OSS sent a total of %d messages to workers.\n", totalMessages);
    fclose(logf);    
    return 0;
}

/* [tryGrantRequest]: handle resource requests from process in OS simulator
    - [procIndex]: index of process making request in process table
    - [request]: array with # of instances requested (+) or released (-) for each resource class
    - if enough resources available to satisfy request, allocate and return 1
        - loop through each resource class again to update resource table
            - if request[i] > 0, allocate requested instances to process and decrease availableInstances
            - if request[i] < 0, release instances from process and increase availableInstances
    - if not enough resources, return 0 to indicate process should be blocked

int tryGrantRequest(int procIndex, int request[RESOURCE_CLASSES]) {
    // Check if enough resources are available
    for (int i = 0; i < RESOURCE_CLASSES; ++i) {
        if (request[i] > 0 && resourceTable[i].availableInstances < request[i])
            return 0;
    }
    // Grant resources
    for (int i = 0; i < RESOURCE_CLASSES; ++i) {
        if (request[i] > 0) {
            resourceTable[i].availableInstances -= request[i];
            resourceTable[i].allocated[procIndex] += request[i];
        }
        if (request[i] < 0) {
            int release = -request[i];
            if (resourceTable[i].allocated[procIndex] >= release) {
                resourceTable[i].allocated[procIndex] -= release;
                resourceTable[i].availableInstances += release;
            }
        }
    }
    return 1;
} */
