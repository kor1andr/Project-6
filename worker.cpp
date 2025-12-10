#include <iostream>
#include <cstdlib>
#include <unistd.h>         // getpid(), getppid()
#include <sys/ipc.h>        // shmat()
#include <sys/shm.h>        // shmat(), shmdt()
#include <sys/msg.h>        // msgget(), msgsnd(), msgrcv()
#include <signal.h>
#include <ctime>            // srand, rand

#define PROCESS_PAGES 16
#define PAGE_SIZE 1024

// SimClock
struct SimClock {
    unsigned int seconds;
    unsigned int nanoseconds;
};

struct MsgBuf {
    long mtype;
    int status;
    int quantum;
    int address;
    int rw;
    int result;
};

// Signal handler for SIGTERM
void handle_sigterm(int) {
    std::cout << "WORKER: Received SIGTERM, exiting immediately." << std::endl;
    exit(0);
}

// MAIN
    // Check for # of args: program name, seconds, nanoseconds, shm_id, msq_id
int main(int argc, char* argv[]) {
    signal(SIGTERM, handle_sigterm);

    // If not enough args, print error and example usage
    if (argc < 5) {
        std::cerr << "[ERROR] Not enough arguments provided.\n";
        std::cout << "[Example] ./worker <seconds> <nanoseconds> <shm_id> <msq_id>\n";
        return 1;
    }

    // Parse args
        // [std::atoi] = convert arg from string --> int and store in respective variable
    int intervalSec = std::atoi(argv[1]);
    int intervalNano = std::atoi(argv[2]);
    int shm_id = std::atoi(argv[3]);
    int msq_id = std::atoi(argv[4]);

    // SimClock* = pointer to SimClock struct to access shared memory as a clock
        // [shmat()]: attach shm segment to process's address space so it can be accessed
        // [nullptr, 0] = let system choose address to attach segment, default flags
    SimClock* clock = (SimClock*)shmat(shm_id, nullptr, 0);
    // If shmat() fails, print error and exit
    if (clock == (void*) -1) {
        std::cerr << "WORKER: shmat failed.\n";
        return 1;
    }

    // Retrieve and store PID + PPID
    pid_t pid = getpid();
    pid_t ppid = getppid();
    // Seed random number generated with current time + PID so each worker process gets different sequence
    srand(time(NULL) ^ pid);

    int totalCpuUsed = 0;
    int cpuBurstLimit = intervalSec * 1000000000 + intervalNano;
    int done = 0;

    // Store start time from shared clock
    int startSec = clock->seconds;
    int startNano = clock->nanoseconds;
    // Calculate termination time (start time + interval)
    int termSec = startSec + intervalSec;
    int termNano = startNano + intervalNano;
    // Handle nanoseconds overflow; If termNano >= 1 billion, convert excess to seconds ((termNano % 1e9) + termsec)
    if (termNano >= 1000000000) {
        termSec += termNano / 1000000000;
        termNano = termNano % 1000000000;
    }

    // Print startup info (PID, PPID, system clock, term time)
    std::cout << "WORKER PID: " << pid << ", PPID: " << ppid << std::endl;
    std::cout << "SysClockS: " << startSec << " SysClockNano: " << startNano << std::endl;
    std::cout << "TermTimeS: " << termSec << " TermTimeNano: " << termNano << std::endl;
    std::cout << "--Just Starting" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    // [messagesRecieved]: Track # of messages received from OSS
    int messagesReceived = 0;

    // MAIN LOOP
    while (!done) {
        MsgBuf msg;
        // [msgrcv]: receive message from OSS with mtype == this worker's PID (so worker only receives messages intended for it)
        msgrcv(msq_id, &msg, sizeof(MsgBuf) - sizeof(long), pid, 0);
        // Increment messages received count
        messagesReceived++;

        // Read current time from shared clock
        int currentSec = clock->seconds;
        int currentNano = clock->nanoseconds;
        if (currentSec > termSec || (currentSec == termSec && currentNano >= termNano)) {
            // Send termination message to OSS
            MsgBuf termMsg;
            termMsg.mtype = pid + 1000;   // OSS expects replies on pid+1000
            termMsg.status = 0;           // 0 = terminating
            termMsg.result = -1;          // negative result signals termination
            msgsnd(msq_id, &termMsg, sizeof(MsgBuf) - sizeof(long), 0);

            std::cout << "--Terminating after sending message back to OSS after " << messagesReceived << " received messages." << std::endl;
            std::cout << "WORKER PID: " << pid << " is exiting now." << std::endl;
            break;
        }

        // MAKE MEMORY REQUEST
            // pick a random page number 
                // [rand()]: generate psuedo-random int
                // [%]: modulus to limit range within valid page numbers (0 to PROCESS_PAGES-1)
            int page = rand() % PROCESS_PAGES;
            // pick a random offset within the selected page
                // [% PAGE_SIZE]: limit offset to within page size (0 to PAGE_SIZE-1)
            int offset = rand() % PAGE_SIZE;
            // calculate actual memory address being accessed
                // [address] = (page number * PAGE_SIZE) + offset
            int address = page * PAGE_SIZE + offset;
            // randomly decide read or write
                // 70% read (0), 30% write (1)
            int rw = (rand() % 100 < 70) ? 0 : 1;

            // Send memory request to OSS
            MsgBuf request;
            request.mtype = pid;
            request.status = 1;
            request.address = address;
            request.rw = rw;
            msgsnd(msq_id, &request, sizeof(MsgBuf) - sizeof(long), 0);

            // Wait for oss to reply
            msgrcv(msq_id, &msg, sizeof(MsgBuf) - sizeof(long), pid + 1000, 0);

            // If result == 0, denied (should not happen); 1 = granted; 2 = page fault (waited)
            if (msg.result == 0) {
                std::cerr << "WORKER: Resource denied, exiting." << std::endl;
                break;
            } else if (msg.result == 2) {
                std::cout << "WORKER: Page fault, waiting for resource." << std::endl;
                // Wait for OSS to notify when page available
                msgrcv(msq_id, &msg, sizeof(MsgBuf) - sizeof(long), pid + 1000, 0);
            }
    }

    shmdt(clock);
    return 0;
}
