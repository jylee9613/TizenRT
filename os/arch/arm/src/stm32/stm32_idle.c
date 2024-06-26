/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
/****************************************************************************
 *  arch/arm/src/stm32/stm32_idle.c
 *
 *   Copyright (C) 2011-2012 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <arch/board/board.h>
#include <tinyara/config.h>
#include <debug.h>

#include <tinyara/arch.h>
#include <tinyara/pm/pm.h>

#include <arch/irq.h>

#include "chip.h"
#include "stm32_pm.h"
#include "up_internal.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Does the board support an IDLE LED to indicate that the board is in the
 * IDLE state?
 */

#if defined(CONFIG_ARCH_LEDS) && defined(LED_IDLE)
#define BEGIN_IDLE() board_led_on(LED_IDLE)
#define END_IDLE()   board_led_off(LED_IDLE)
#else
#define BEGIN_IDLE()
#define END_IDLE()
#endif

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_idlepm
 *
 * Description:
 *   Perform IDLE state power management.
 *
 ****************************************************************************/

#ifdef CONFIG_PM
static void up_idlepm(void)
{
	static enum pm_state_e oldstate = PM_NORMAL;
	enum pm_state_e newstate;
	irqstate_t flags;
	int ret;

	/* Decide, which power saving level can be obtained */

	newstate = pm_checkstate();

	/* Check for state changes */

	if (newstate != oldstate) {
		flags = irqsave();

		/* Perform board-specific, state-dependent logic here */

		sllvdbg("newstate= %d oldstate=%d\n", newstate, oldstate);

		/* Then force the global state change */

		ret = pm_changestate(newstate);
		if (ret < 0) {
			/* The new state change failed, revert to the preceding state */

			(void)pm_changestate(oldstate);
		} else {
			/* Save the new state */

			oldstate = newstate;
		}

		/* MCU-specific power management logic */

		switch (newstate) {
		case PM_NORMAL:
			break;

		case PM_IDLE:
			break;

		case PM_STANDBY:
			stm32_pmstop(true);
			break;

		case PM_SLEEP:
			(void)stm32_pmstandby();
			break;

		default:
			break;
		}

		irqrestore(flags);
	}
}
#else
#define up_idlepm()
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_idle
 *
 * Description:
 *   up_idle() is the logic that will be executed when their is no other
 *   ready-to-run task.  This is processor idle time and will continue until
 *   some interrupt occurs to cause a context switch from the idle task.
 *
 *   Processing in this state may be processor-specific. e.g., this is where
 *   power management operations might be performed.
 *
 ****************************************************************************/

void up_idle(void)
{
#if defined(CONFIG_SUPPRESS_INTERRUPTS) || defined(CONFIG_SUPPRESS_TIMER_INTS)
	/* If the system is idle and there are no timer interrupts, then process
	 * "fake" timer interrupts. Hopefully, something will wake up.
	 */

	sched_process_timer();
#else

	/* Perform IDLE mode power management */

	up_idlepm();

	/* Sleep until an interrupt occurs to save power.
	 *
	 * NOTE:  There is an STM32F107 errata that is fixed by the following
	 * workaround:
	 *
	 * "2.17.11 Ethernet DMA not working after WFI/WFE instruction
	 *  Description
	 *  If a WFI/WFE instruction is executed to put the system in sleep mode
	 *    while the Ethernet MAC master clock on the AHB bus matrix is ON and all
	 *    remaining masters clocks are OFF, the Ethernet DMA will be not able to
	 *    perform any AHB master accesses during sleep mode."
	 *
	 *  Workaround
	 *    Enable DMA1 or DMA2 clocks in the RCC_AHBENR register before
	 *    executing the WFI/WFE instruction."
	 *
	 * Here the workaround is just to avoid SLEEP mode for the connectivity
	 * line parts if Ethernet is enabled.  The errate recommends a  more
	 * general solution:  Enabling DMA1/2 clocking in stm32f10xx_rcc.c if the
	 * STM32107 Ethernet peripheral is enabled.
	 */

#if !defined(CONFIG_STM32_CONNECTIVITYLINE) || !defined(CONFIG_STM32_ETHMAC)
#if !(defined(CONFIG_DEBUG_SYMBOLS) && defined(CONFIG_STM32_DISABLE_IDLE_SLEEP_DURING_DEBUG))
	BEGIN_IDLE();
	asm("WFI");
	END_IDLE();
#endif
#endif
#endif
}
