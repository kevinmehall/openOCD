/***************************************************************************
 *   Copyright (C) 2011 by Julius Baxter                                   *
 *   julius@opencores.org                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef OR1K_H
#define OR1K_H


#include <helper/types.h>

struct target;

/* OR1K registers */
#define OR1KNUMCOREREGS (32 + 3)

enum or1k_reg_nums {
	OR1K_REG_R0 = 0,
	OR1K_REG_R1,
	OR1K_REG_R2,
	OR1K_REG_R3,
	OR1K_REG_R4,
	OR1K_REG_R5,
	OR1K_REG_R6,
	OR1K_REG_R7,
	OR1K_REG_R8,
	OR1K_REG_R9,
	OR1K_REG_R10,
	OR1K_REG_R11,
	OR1K_REG_R12,
	OR1K_REG_R13,
	OR1K_REG_R14,
	OR1K_REG_R15,
	OR1K_REG_R16,
	OR1K_REG_R17,
	OR1K_REG_R18,
	OR1K_REG_R19,
	OR1K_REG_R20,
	OR1K_REG_R21,
	OR1K_REG_R22,
	OR1K_REG_R23,
	OR1K_REG_R24,
	OR1K_REG_R25,
	OR1K_REG_R26,
	OR1K_REG_R27,
	OR1K_REG_R28,
	OR1K_REG_R29,
	OR1K_REG_R30,
	OR1K_REG_R31,
	OR1K_REG_PPC,
	OR1K_REG_NPC,
	OR1K_REG_SR
};


struct or1k_common
{
	struct or1k_jtag jtag;
	struct reg_cache *core_cache;
	uint32_t core_regs[OR1KNUMCOREREGS];
};

static inline struct or1k_common *
target_to_or1k(struct target *target)
{
	return (struct or1k_common*)target->arch_info;
}

struct or1k_core_reg
{
	uint32_t list_num; /* Index in register cache */
	uint32_t spr_num; /* Number in architecture's SPR space */
	struct target *target;
	struct or1k_common *or1k_common;

};

/* Make this available to or1k_jtag.h */
extern struct or1k_core_reg or1k_core_reg_list_arch_info[OR1KNUMCOREREGS];

/*! ORBIS32 Trap instruction */
#define OR1K_TRAP_INSTR  0x21000001

/* OR1K Debug registers and bits needed for resuming */
#define OR1K_DMR1_CPU_REG_ADD ((6<<11)+16)/* Debug Mode Register 1 0x3010 */
#define OR1K_DMR2_CPU_REG_ADD ((6<<11)+17)/* Debug Mode Register 2 0x3011 */
#define OR1K_DSR_CPU_REG_ADD	 ((6<<11)+20)/* Debug Stop Register 0x3014 */
#define OR1K_DRR_CPU_REG_ADD  ((6<<11)+21)/* Debug Reason Register 0x3015 */
#define OR1K_DMR1_ST 	0x00400000	/* Single-step trace */
#define OR1K_DMR2_WGB   	0x003ff000	/* Watchpoints generating breakpoint */
#define OR1K_DSR_TE	0x00002000	/* Trap exception */


#endif
