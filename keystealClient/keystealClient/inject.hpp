//
//  inject.hpp
//  keystealClient
//
//  Created by Linus Henze on 22.01.19.
//  Copyright © 2019 Linus Henze. All rights reserved.
//

#ifndef inject_hpp
#define inject_hpp

#include <stdio.h>
#include <mach/mach.h>

void installHook(void *real, void *repl);
void inject_fake_task_port(mach_port_t port);

#endif /* inject_hpp */
