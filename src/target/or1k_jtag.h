/***************************************************************************
 *   Copyright (C) 2011 Julius Baxter                                      *
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
#ifndef OR1K_JTAG
#define OR1K_JTAG


/* tap instructions - Mohor JTAG TAP */
#define OR1K_TAP_INST_IDCODE 0x2
#define OR1K_TAP_INST_DEBUG 0x8


/* Mohor SoC debug interface defines */

/* Module selection 4-bits */
#define OR1K_MOHORDBGIF_MODULE_WB   0x0
#define OR1K_MOHORDBGIF_MODULE_CPU0 0x1
#define OR1K_MOHORDBGIF_MODULE_CPU1 0x2 /* Not implemented/used */

/* Wishbone module commands */
#define OR1K_MOHORDBGIF_WB_MODULE_CMD_GO 0x0
#define OR1K_MOHORDBGIF_WB_MODULE_CMD_READ 0x1
#define OR1K_MOHORDBGIF_WB_MODULE_CMD_WRITE 0x2

/* Wishbone bus access command defines */
#define OR1K_MOHORDBGIF_WB_ACC_WRITE8  0x0
#define OR1K_MOHORDBGIF_WB_ACC_WRITE16 0x1
#define OR1K_MOHORDBGIF_WB_ACC_WRITE32 0x2
#define OR1K_MOHORDBGIF_WB_ACC_READ8   0x4
#define OR1K_MOHORDBGIF_WB_ACC_READ16  0x5
#define OR1K_MOHORDBGIF_WB_ACC_READ32  0x6

/* CPU module command defines */
#define OR1K_MOHORDBGIF_CPU_ACC_WRITE  0x2
#define OR1K_MOHORDBGIF_CPU_ACC_READ  0x6

/* CPU module commands */
#define OR1K_MOHORDBGIF_CPU_MODULE_CMD_GO 0x0
#define OR1K_MOHORDBGIF_CPU_MODULE_CMD_READ 0x1
#define OR1K_MOHORDBGIF_CPU_MODULE_CMD_WRITE 0x2
#define OR1K_MOHORDBGIF_CPU_MODULE_CMD_CTRL_READ 0x3
#define OR1K_MOHORDBGIF_CPU_MODULE_CMD_CTRL_WRITE 0x4

/* CPU module control register bits */
#define OR1K_MOHORDBGIF_CPU_CR_RESET 1
#define OR1K_MOHORDBGIF_CPU_CR_STALL 2

#define OR1K_CPU_STALLED 0x1

/* Module select response status codes */
#define OR1K_MOHORDBGIF_MODULE_SELECT_OK 0x0
#define OR1K_MOHORDBGIF_MODULE_SELECT_CRC_ERROR 0x1
#define OR1K_MOHORDBGIF_MODULE_SELECT_MODULE_NOT_EXIST 0x2

/* Command status codes */
#define OR1K_MOHORDBGIF_CMD_OK 0x0
#define OR1K_MOHORDBGIF_CMD_CRC_ERROR 0x1
#define OR1K_MOHORDBGIF_CMD_WB_ERROR 0x4
#define OR1K_MOHORDBGIF_CMD_OURUN_ERROR 0x8



struct or1k_jtag
{
	struct jtag_tap *tap;
};

int or1k_jtag_init(struct or1k_jtag *jtag_info);

/* Currently hard set in functions to 32-bits */
int or1k_jtag_read_cpu(struct or1k_jtag *jtag_info,
		uint32_t addr, uint32_t *value);
int or1k_jtag_write_cpu(struct or1k_jtag *jtag_info,
		uint32_t addr, uint32_t value);

int or1k_jtag_read_cpu_cr(struct or1k_jtag *jtag_info,
		uint32_t *value);

int or1k_jtag_write_cpu_cr(struct or1k_jtag *jtag_info,
			   uint32_t stall, uint32_t reset);


int or1k_jtag_read_memory32(struct or1k_jtag *jtag_info, 
		uint32_t addr, int count, uint32_t *buffer);
int or1k_jtag_read_memory16(struct or1k_jtag *jtag_info, 
		uint32_t addr, int count, uint16_t *buffer);
int or1k_jtag_read_memory8(struct or1k_jtag *jtag_info, 
		uint32_t addr, int count, uint8_t *buffer);

int or1k_jtag_write_memory32(struct or1k_jtag *jtag_info, 
		uint32_t addr, int count, const uint32_t *buffer);
int or1k_jtag_write_memory16(struct or1k_jtag *jtag_info, 
		uint32_t addr, int count, const uint16_t *buffer);
int or1k_jtag_write_memory8(struct or1k_jtag *jtag_info, 
		uint32_t addr, int count, const uint8_t *buffer);


int or1k_jtag_read_regs(struct or1k_jtag *jtag_info, uint32_t *regs);
int or1k_jtag_write_regs(struct or1k_jtag *jtag_info, uint32_t *regs);


#endif /* OR1K_JTAG */

