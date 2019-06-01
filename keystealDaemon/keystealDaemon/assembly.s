//
//  assembly.s
//  keystealDaemon
//
//  Created by Linus Henze on 22.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

.intel_syntax noprefix

.text

#define DEFINE_MACH_TRAP(name, number) .globl name; name: mov rax, 0x1000000; add rax, number; mov r10, rcx; syscall; ret

DEFINE_MACH_TRAP(_real_mach_msg, 31)
