/***************************************************************************
 *   Support for the adv_dbg_if. It only support ADBG_OPT_HISPEED flagged  *
 *   version of the IP.                                                    *
 *                                                                         *
 *   Copyright (C) 2012 Franck Jullien                                     *
 *   franck.jullien at elec4fun.fr                                            *
 *                                                                         *
 *   Inpired from adv_jtag_bridge which is:                                *
 *   Copyright (C) 2008-2010 Nathan Yawn                                   *
 *   nyawn at opencores.net                                                   *
 *                                                                         *
 *   And the Mohor interface version of this file which is:                *
 *   Copyright (C) 2011 Julius Baxter                                      *
 *   julius at opencores.org                                                  *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "target.h"
#include "helper/types.h"
#include "jtag/jtag.h"
#include "or1k_jtag.h"
#include "or1k.h"
#include "altera_virtual_jtag.h"
#include "or1k_jtag_adv.h"

//#define VERBOSE_SLD_NODE

#define ALTERA_VJTAG
#define MORE_SPEED_NO_CONTROL

#define MAX_READ_STATUS_WAIT		10
#define MAX_READ_BUSY_RETRY		2
#define MAX_READ_CRC_RETRY		2
#define MAX_WRITE_CRC_RETRY		2
#define BURST_READ_READY		1
#define MAX_BUS_ERRORS			2

static int or1k_jtag_inited = 0;
static int or1k_jtag_module_selected = -1;

/* Currently selected internal register in each module
 * cuts down on unnecessary transfers
 */
unsigned long current_reg_idx[DBG_MAX_MODULES];

#ifdef ALTERA_VJTAG
#ifdef VERBOSE_SLD_NODE
static char * id_to_string(unsigned char id)
{
	switch(id) {
		case VJTAG_NODE_ID          : return "Virtual JTAG";
		case JTAG_TO_AVALON_NODE_ID : return "JTAG to avalon bridge";
		case SIGNAL_TAP_NODE_ID     : return "Signal TAP";
	}
	return "unknown";
}
#endif
static unsigned char guess_addr_width(unsigned char number_of_nodes)
{
	unsigned char width = 0;

	while (number_of_nodes) {
		number_of_nodes >>= 1;
		width ++;
	}

	return width;
}
#endif

const char * chain_name[] = {"WISHBONE", "CPU0", "CPU1", "JSP"};

uint32_t adbg_compute_crc(uint32_t crc_in, uint32_t data_in, int length_bits)
{
	int i;
	unsigned int d, c;
	uint32_t crc_out = crc_in;

	for (i = 0; i < length_bits; i = i+1) {
		d = ((data_in >> i) & 0x1) ? 0xffffffff : 0;
		c = (crc_out & 0x1) ? 0xffffffff : 0;
		crc_out = crc_out >> 1;
		crc_out = crc_out ^ ((d ^ c) & ADBG_CRC_POLY);
	}

	return crc_out;
}

int or1k_jtag_init(struct or1k_jtag *jtag_info)
{
	union hub_info hub;
	union node_info node;
	struct scan_field field;
	struct jtag_tap *tap;
#ifdef ALTERA_VJTAG
	int i;
	int node_index;
	int vjtag_node_address = 0;
#endif
	uint8_t t[8];
	uint8_t ret;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	hub.dword = 0;
	node.dword = 0;

#ifdef ALTERA_VJTAG
	LOG_DEBUG("Initialising Altera Virtual JTAG TAP for Advanced Debug Interface");

	/* Ensure TAP is reset - maybe not necessary*/
	jtag_add_tlr();

	/* Select VIR */
	field.num_bits = tap->ir_length;
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, ALTERA_CYCLONE_CMD_VIR);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);

	/* The SLD hub contains the HUB IP Configuration Register and SLD_NODE_INFO
	 * register for each SLD node in the design. The HUB IP configuration register provides
	 * information needed to determine the dimensions of the USER1 DR chain. The
	 * SLD_NODE_INFO register is used to determine the address mapping for Virtual
	 * JTAG instance in your design. This register set is shifted out by issuing the
	 * HUB_INFO instruction. Both the ADDR bits for the SLD hub and the HUB_INFO
	 * instruction is 0 × 0.
	 * Because m and n are unknown at this point, the DR register
	 * (ADDR bits + VIR_VALUE) must be filled with zeros. Shifting a sequence of 64 zeroes
	 * into the USER1 DR is sufficient to cover the most conservative case for m and n.
	 */

	field.num_bits= 64;
	field.out_value = t;
	field.in_value = NULL;
	memset(t, 0, 8);
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);

	/* Select VDR */
	field.num_bits = tap->ir_length;
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, ALTERA_CYCLONE_CMD_VDR);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);

	jtag_execute_queue();

	for(i = 0;i < 8;i++) {
		field.num_bits= 4;
		field.out_value = NULL;
		field.in_value = &ret;
		jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
		jtag_execute_queue();
		hub.dword = ((hub.dword >> 4) | ((ret & 0xf) << 28));
	}

#ifdef VERBOSE_SLD_NODE
	LOG_DEBUG("\nSLD HUB Configuration register");
	LOG_DEBUG("------------------------------");
	LOG_DEBUG("m_width         = %d", hub.m_width);
	LOG_DEBUG("manufacturer_id = 0x%02x", hub.manufacturer_id);
	LOG_DEBUG("nb_of_node      = %d", hub.nb_of_node);
	LOG_DEBUG("version         = %d\n", hub.version);
	LOG_DEBUG("VIR length      = %d", guess_addr_width(hub.nb_of_node) + hub.m_width);
#endif

	/* Because the number of SLD nodes is now known, the Nodes on the hub can be
	 * enumerated by repeating the 8 four-bit nibble scans, once for each Node,
	 * to yield the SLD_NODE_INFO register of each Node. The DR nibble shifts
	 * are a continuation of the HUB_INFO DR shift used to shift out the Hub IP
	 * Configuration register.
	 */

	for(node_index = 0;node_index < hub.nb_of_node;node_index++) {

		for(i = 0;i < 8;i++) {
			field.num_bits= 4;
			field.out_value = NULL;
			field.in_value = &ret;
			jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
			jtag_execute_queue();
			node.dword = ((node.dword >> 4) | ((ret & 0xf) << 28));
		}
#ifdef VERBOSE_SLD_NODE
		LOG_DEBUG("\nNode info register");
		LOG_DEBUG("--------------------");
		LOG_DEBUG("instance_id     = %d",node.instance_id);
		LOG_DEBUG("manufacturer_id = 0x%02x", node.manufacturer_id);
		LOG_DEBUG("node_id         = %d (%s)", node.node_id, id_to_string(node.node_id));
		LOG_DEBUG("version         = %d\n", node.version);
#endif
		if(node.node_id == VJTAG_NODE_ID) vjtag_node_address = node_index + 1;
	}

	/* Select VIR */
	field.num_bits = tap->ir_length;
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, ALTERA_CYCLONE_CMD_VIR);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);

	/* Send the DEBUG command */
	field.num_bits = guess_addr_width(hub.nb_of_node) + hub.m_width;
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, (vjtag_node_address << hub.m_width) | ALT_VJTAG_CMD_DEBUG);
	field.in_value = NULL;
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);

	/* Select VDR */
	field.num_bits = tap->ir_length;
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, ALTERA_CYCLONE_CMD_VDR);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);

	jtag_execute_queue();

#else // Opencores TAP

	LOG_DEBUG("Initialising OpenCores JTAG TAP for Advanced Debug Interface");

	field.num_bits = tap->ir_length;
	field.out_value = t;
	/* OpenCores Mohor JTAG TAP-specific */
	buf_set_u32(t, 0, field.num_bits, OR1K_TAP_INST_DEBUG);
	field.in_value = &ret;

	/* Ensure TAP is reset - maybe not necessary*/
	jtag_add_tlr();

	jtag_add_ir_scan(tap, &field, TAP_IDLE);
	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR("Setting TAP's IR to DEBUG failed");
		return ERROR_FAIL;
	}

#endif

	/* TAP should now be configured to communicate with debug interface */
	or1k_jtag_inited = 1;

	/* TAP reset - not sure what state debug module chain is in now */
	or1k_jtag_module_selected = -1;

	memset(current_reg_idx, 0, sizeof(unsigned long) * DBG_MAX_MODULES);

	return ERROR_OK;

}

/* Selects one of the modules in the debug unit (e.g. wishbone unit, CPU0, etc.) */
int adbg_select_module(struct or1k_jtag *jtag_info, int chain)
{
	struct jtag_tap *tap;
	struct scan_field field;
	uint8_t data;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	if (or1k_jtag_module_selected == chain)
		return ERROR_OK;

	/* MSB of the data out must be set to 1, indicating a module select command */
	data = chain | (1 << DBG_MODULE_SELECT_REG_SIZE);

	LOG_DEBUG("Select module: %s", chain_name[chain]);

	field.num_bits = 3;
	field.out_value = &data;
	field.in_value = NULL;
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);

	jtag_execute_queue();

	or1k_jtag_module_selected = chain;

	return ERROR_OK;
}

/* Set the index of the desired register in the currently selected module
 * 1 bit module select command
 * 4 bits opcode
 * n bits index
 */
int adbg_select_ctrl_reg(struct or1k_jtag *jtag_info, unsigned long regidx)
{
	struct jtag_tap *tap;
	struct scan_field field;
	int index_len = 0;
	uint32_t data;
	uint32_t opcode;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	LOG_DEBUG("Select control register: %ld", regidx);

	/* If this reg is already selected, don't do a JTAG transaction */
	if(current_reg_idx[or1k_jtag_module_selected] == regidx)
		return ERROR_OK;

	switch(or1k_jtag_module_selected) {
		case DC_WISHBONE:
			index_len = DBG_WB_REG_SEL_LEN;
			opcode = DBG_WB_CMD_IREG_SEL;
			break;
		case DC_CPU0:
			index_len = DBG_CPU0_REG_SEL_LEN;
			opcode = DBG_CPU0_CMD_IREG_SEL;
			break;
		case DC_CPU1:
			index_len = DBG_CPU1_REG_SEL_LEN;
			opcode = DBG_CPU1_CMD_IREG_SEL;
			break;
		default:
			LOG_DEBUG("ERROR! Illegal debug chain selected while selecting control register!");
			return ERROR_FAIL;
	}

	/* Set up the data */
	data = (opcode & ~(1 << DBG_WB_OPCODE_LEN)) << index_len;  /* MSB must be 0 to access modules */
	data |= regidx;

	//LOG_DEBUG("Selreg: data is 0x%X (opcode = 0x%X)\n", data, opcode);

	field.num_bits = 5 + index_len;
	field.out_value = (uint8_t *)&data;
	field.in_value = NULL;
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);

	jtag_execute_queue();

	current_reg_idx[or1k_jtag_module_selected] = regidx;

	return ERROR_OK;
}

/* Sends out a generic command to the selected debug unit module, LSB first.  Fields are:
 * MSB: 1-bit module command
 * 4-bit opcode
 * m-bit register index
 * n-bit data (LSB)
 * Note that in the data array, the LSB of data[0] will be sent first,
 * (and become the LSB of the command)
 * up through the MSB of data[0], then the LSB of data[1], etc.
 */
int adbg_ctrl_write(struct or1k_jtag *jtag_info, unsigned long regidx, uint32_t *cmd_data, int length_bits)
{
	struct jtag_tap *tap;
	struct scan_field field[10]; /* We assume no more than 320 databits */
	uint32_t data;
	uint32_t opcode;
	int index_len = 0;
	int nb_fields = 0;
	int length_bits_32;
	int spare_bits;
	int i = 0;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	LOG_DEBUG("Write control register %ld: 0x%08X", regidx, cmd_data[0]);

	if(adbg_select_ctrl_reg(jtag_info, regidx) != ERROR_OK)
		return ERROR_FAIL;

	switch(or1k_jtag_module_selected) {
		case DC_WISHBONE:
			index_len = DBG_WB_REG_SEL_LEN;
			opcode = DBG_WB_CMD_IREG_WR;
			break;
		case DC_CPU0:
			index_len = DBG_CPU0_REG_SEL_LEN;
			opcode = DBG_CPU0_CMD_IREG_WR;
			break;
		case DC_CPU1:
			index_len = DBG_CPU1_REG_SEL_LEN;
			opcode = DBG_CPU1_CMD_IREG_WR;
			break;
		default:
			LOG_DEBUG("ERROR! Illegal debug chain selected (%i) while doing control write!", or1k_jtag_module_selected);
			return ERROR_FAIL;
	}

	length_bits_32 = length_bits / 32;
	spare_bits = length_bits % 32;

	/* Set up the data */
	data = (opcode & ~(1 << DBG_WB_OPCODE_LEN)) << index_len;  /* MSB must be 0 to access modules */
	data |= regidx;

	for(i = 0 ; i < length_bits_32; i++) {
		field[i].num_bits = 32;
		field[i].out_value = (uint8_t *)&cmd_data[i * 4];
		field[i].in_value = NULL;
		nb_fields++;
	}

	if(spare_bits) {
		field[i].num_bits = spare_bits;
		field[i].out_value = (uint8_t *)&cmd_data[i * 4];
		field[i].in_value = NULL;
		nb_fields++;
	}

	field[i + 1].num_bits = 5 + index_len;
	field[i + 1].out_value = (uint8_t *)&data;
	field[i + 1].in_value = NULL;

	jtag_add_dr_scan(tap, nb_fields + 1, &field[0], TAP_IDLE);

	jtag_execute_queue();

	return ERROR_OK;
}

/* Reads control register (internal to the debug unit)
 * Currently only 1 register in the CPU module, so no register select
 */
int adbg_ctrl_read(struct or1k_jtag *jtag_info, unsigned long regidx, uint32_t *data, int databits)
{
	struct jtag_tap *tap;
	struct scan_field field[10]; /* We assume no more than 320 databits */
	uint32_t outdata;
	int opcode;
	int opcode_len;
	int databits_32;
	int spare_bits;
	int i = 0;
	int nb_fields = 0;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	LOG_DEBUG("Read control register %ld", regidx);

	if(adbg_select_ctrl_reg(jtag_info, regidx) != ERROR_OK)
		return ERROR_FAIL;

	/* There is no 'read' command, We write a NOP to read */
	switch(or1k_jtag_module_selected) {
		case DC_WISHBONE:
			opcode = DBG_WB_CMD_NOP;
			opcode_len = DBG_WB_OPCODE_LEN;
			break;
		case DC_CPU0:
			opcode = DBG_CPU0_CMD_NOP;
			opcode_len = DBG_CPU0_OPCODE_LEN;
			break;
		case DC_CPU1:
			opcode = DBG_CPU1_CMD_NOP;
			opcode_len = DBG_CPU1_OPCODE_LEN;
			break;
		default:
			LOG_DEBUG("ERROR! Illegal debug chain selected while doing control read!");
			 return ERROR_FAIL;
	}

	outdata = opcode & ~(0x1 << opcode_len);  /* Zero MSB = op for module, not top-level debug unit */

	databits_32 = databits / 32;
	spare_bits = databits % 32;

	for(i = 0 ; i < databits_32; i++) {
		field[i].num_bits = 32;
		field[i].out_value = (uint8_t *)&outdata;
		field[i].in_value = (uint8_t *)&data[i * 4];
		nb_fields++;
	}

	if(spare_bits) {
		field[i].num_bits = spare_bits;
		field[i].out_value = (uint8_t *)&outdata;
		field[i].in_value = (uint8_t *)&data[i * 4];
		nb_fields++;
	}

	field[i + 1].num_bits = opcode_len + 1;
	field[i + 1].out_value = (uint8_t *)&outdata;
	field[i + 1].in_value = NULL;

	jtag_add_dr_scan(tap, nb_fields + 1, &field[0], TAP_IDLE);

	jtag_execute_queue();

	return ERROR_OK;
}

/* sends out a burst command to the selected module in the debug unit (MSB to LSB):
 * 1-bit module command
 * 4-bit opcode
 * 32-bit address
 * 16-bit length (of the burst, in words)
 */
int adbg_burst_command(struct or1k_jtag *jtag_info, unsigned int opcode, unsigned long address, int length_words)
{
	struct jtag_tap *tap;
	struct scan_field field[10]; /* We assume no more than 320 databits */
	uint32_t data[2];

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	/* Set up the data */
	data[0] = length_words | (address << 16);
	data[1] = ((address >> 16) | ((opcode & 0xf) << 16)) & ~(0x1<<20); /* MSB must be 0 to access modules */

	//LOG_DEBUG("Burst op %i adr 0x%lX len %i\n", opcode, address, length_words);
	//LOG_DEBUG("Value = %x%08x\n", data[1], data[0]);

	field[0].num_bits = 32;
	field[0].out_value = (uint8_t *)&data[0];
	field[0].in_value = NULL;

	field[1].num_bits = 21;
	field[1].out_value = (uint8_t *)&data[1];
	field[1].in_value = NULL;

	jtag_add_dr_scan(tap, 2, field, TAP_IDLE);

	jtag_execute_queue();

	return ERROR_OK;
}


int adbg_wb_burst_read(struct or1k_jtag *jtag_info, int word_size_bytes,
			int word_count, unsigned long start_address, void *data)
{
	struct jtag_tap *tap;
	struct scan_field field[100];/* We assume no more than 3200 databits */
	int i = 0;
	int retry = 0;
	int total_size_bytes;
	int total_size_32;
	int spare_bytes;
	int nb_fields = 0;
	int retry_full_crc = 0;
	int retry_full_busy = 0;
	int bus_error_retries = 0;
	uint8_t opcode;
	uint8_t status;
	uint32_t crc_calc;
	uint32_t crc_read;
	uint8_t *in_buffer;
	uint32_t err_data[2] = {0, 0};
	uint32_t addr;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	LOG_DEBUG("Doing burst read, word size %d, word count %d, start address 0x%08lX", word_size_bytes, word_count, start_address);

	if (word_count <= 0) {
		LOG_DEBUG("Ignoring illegal read burst length (%d)", word_count);
		return ERROR_FAIL;
	}

	/* Select the appropriate opcode */
	switch (or1k_jtag_module_selected) {
		case DC_WISHBONE:
			if (word_size_bytes == 1) opcode = DBG_WB_CMD_BREAD8;
			else if (word_size_bytes == 2) opcode = DBG_WB_CMD_BREAD16;
			else if (word_size_bytes == 4) opcode = DBG_WB_CMD_BREAD32;
			else {
				LOG_DEBUG("Tried burst read with invalid word size (%0x), defaulting to 4-byte words", word_size_bytes);
				opcode = DBG_WB_CMD_BREAD32;
			}
			break;
		case DC_CPU0:
			if (word_size_bytes == 4) opcode = DBG_CPU0_CMD_BREAD32;
			else {
				LOG_DEBUG("Tried burst read with invalid word size (%0x), defaulting to 4-byte words", word_size_bytes);
				opcode = DBG_CPU0_CMD_BREAD32;
			}
			break;
		case DC_CPU1:
			if (word_size_bytes == 4) opcode = DBG_CPU1_CMD_BREAD32;
			else {
				LOG_DEBUG("Tried burst read with invalid word size (%0x), defaulting to 4-byte words", word_size_bytes);
				opcode = DBG_CPU0_CMD_BREAD32;
			}
			break;
		default:
			LOG_DEBUG("ERROR! Illegal debug chain selected while doing burst read!");
			return 1;
	}

retry_read_full:

	/* Send the BURST READ command, returns TAP to idle state */
	if (adbg_burst_command(jtag_info, opcode, start_address, word_count) != ERROR_OK)
		return ERROR_FAIL;

	/* We do not adjust for the DR length here.  BYPASS regs are loaded with 0,
	 * and the debug unit waits for a '1' status bit before beginning to read data.
	 */

	/* Get 1 status bit, then word_size_bytes*8 bits */
	status = 0;

	field[0].num_bits = 1;
	field[0].out_value = NULL;
	field[0].in_value = (uint8_t *)&status;

	/* Please ensure the jtag driver used doesn't move the tap when the end state is TAP_DRSHIFT.
	 * As we are doing polling on DR value, we need to stay in DRSHIFT state. I had to hack the 
	 * usb_blaster driver to get this behavior.
	 */

	while (!(status & BURST_READ_READY) && retry < MAX_READ_STATUS_WAIT) {
		jtag_add_dr_scan(tap, 1, &field[0], TAP_DRSHIFT);
		jtag_execute_queue();
		retry++;
	}

	if (retry == MAX_READ_STATUS_WAIT) {
		LOG_DEBUG("Burst read timed out\n");
		if (retry_full_busy++ < MAX_READ_BUSY_RETRY)
			goto retry_read_full;
		else
			return ERROR_FAIL;
	}

	total_size_bytes = (word_count * word_size_bytes) + 4;
	total_size_32 = total_size_bytes / 4;
	spare_bytes = total_size_bytes % 4;

	in_buffer = malloc(total_size_bytes);

	for (i = 0;i < total_size_32; i++) {
		field[i].num_bits = 32;
		field[i].out_value = NULL;
		field[i].in_value = &in_buffer[i * 4];
		nb_fields++;
	}

	if (spare_bytes) {
		field[i].num_bits = spare_bytes * 8;
		field[i].out_value = NULL;
		field[i].in_value = &in_buffer[i * 4];
		nb_fields++;
	}

	jtag_add_dr_scan(tap, nb_fields, field, TAP_IDLE);

	jtag_execute_queue();

	memcpy(data, in_buffer, word_count * word_size_bytes);
	memcpy(&crc_read, &in_buffer[word_count * word_size_bytes], 4);

	LOG_DEBUG("CRC read = 0x%08X", crc_read);

	crc_calc = 0xffffffff;
	for (i = 0; i < (word_count * word_size_bytes); i++) {
		crc_calc = adbg_compute_crc(crc_calc, ((uint8_t *)data)[i], 8);
	}

	LOG_DEBUG("CRC calc = 0x%08X", crc_calc);

	if (crc_calc != crc_read) {
		LOG_DEBUG("CRC ERROR! Computed 0x%x, read CRC 0x%x", crc_calc, crc_read);
		if(retry_full_crc++ < MAX_READ_CRC_RETRY)
			goto retry_read_full;
		else {
			free(in_buffer);
			return ERROR_FAIL;
		}
	}
	else
		LOG_DEBUG("CRC OK!");


	/* Now, read the error register, and retry/recompute as necessary */
	if(or1k_jtag_module_selected == DC_WISHBONE) {
#ifndef MORE_SPEED_NO_CONTROL
		adbg_ctrl_read(jtag_info, DBG_WB_REG_ERROR, err_data, 1); /* First, just get 1 bit...read address only if necessary */
#endif
		if(err_data[0] & 0x1) { /* Then we have a problem */

			adbg_ctrl_read(jtag_info, DBG_WB_REG_ERROR, err_data, 33);
			addr = (err_data[0] >> 1) | (err_data[1] << 31);
			LOG_DEBUG("ERROR!  WB bus error during burst read, address 0x%X (index 0x%lX), retrying!", addr, (addr - start_address) / word_size_bytes);

			bus_error_retries++;
			if (bus_error_retries > MAX_BUS_ERRORS) {
				LOG_DEBUG("Max WB bus errors reached during burst read");
				return ERROR_FAIL;
			}

			/* Don't call retry_do(), a JTAG reset won't help a WB bus error */
			err_data[0] = 1;
			adbg_ctrl_write(jtag_info, DBG_WB_REG_ERROR, err_data, 1);  // Write 1 bit, to reset the error register,
			goto retry_read_full;
		}
	}

	free(in_buffer);

	return ERROR_OK;
}

/* Set up and execute a burst write to a contiguous set of addresses */
int adbg_wb_burst_write(struct or1k_jtag *jtag_info, void *data, int word_size_bytes,
			int word_count, unsigned long start_address)
{
	struct scan_field field[100]; /* We assume no more than 3200 databits */
	struct jtag_tap *tap;
	int i = 0;
	int word_size_bits;
	int total_size_bytes;
	int nb_fields = 0;
	int total_size_32;
	int spare_bytes;
	int retry_full_crc = 0;
	int bus_error_retries = 0;
	uint32_t err_data[2] = {0, 0};
	uint8_t opcode;
	uint32_t datawords = 0;
	uint32_t crc_calc;
	uint8_t value;
	uint8_t *out_buffer;
	uint32_t addr;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	if(word_count <= 0) {
		LOG_DEBUG("Ignoring illegal burst write size (%d)", word_count);
		return ERROR_FAIL;
	}

	LOG_DEBUG("Doing burst write, word size %d, word count %d, start address 0x%lx", word_size_bytes, word_count, start_address);

	word_size_bits = word_size_bytes << 3;

	/* Select the appropriate opcode */
	switch (or1k_jtag_module_selected) {
		case DC_WISHBONE:
			if (word_size_bytes == 1) opcode = DBG_WB_CMD_BWRITE8;
			else if (word_size_bytes == 2) opcode = DBG_WB_CMD_BWRITE16;
			else if (word_size_bytes == 4) opcode = DBG_WB_CMD_BWRITE32;
			else {
				LOG_DEBUG("Tried WB burst write with invalid word size (%0x), defaulting to 4-byte words", word_size_bytes);
				opcode = DBG_WB_CMD_BWRITE32;
			}
			break;
		case DC_CPU0:
			if (word_size_bytes == 4) opcode = DBG_CPU0_CMD_BWRITE32;
			else {
				LOG_DEBUG("Tried CPU0 burst write with invalid word size (%0x), defaulting to 4-byte words", word_size_bytes);
				opcode = DBG_CPU0_CMD_BWRITE32;
			}
			break;
		case DC_CPU1:
			if (word_size_bytes == 4) opcode = DBG_CPU1_CMD_BWRITE32;
			else {
				LOG_DEBUG("Tried CPU1 burst write with invalid word size (%0X), defaulting to 4-byte words", word_size_bytes);
				opcode = DBG_CPU0_CMD_BWRITE32;
			}
			break;
		default:
			LOG_DEBUG("ERROR! Illegal debug chain selected while doing burst WRITE!\n");
			return ERROR_FAIL;
	}

retry_full_write:

	/* Send the BURST WRITE command, returns TAP to idle state */
	if (adbg_burst_command(jtag_info, opcode, start_address, word_count) != ERROR_OK)
		return ERROR_FAIL;

	/* Write a start bit so it knows when to start counting */
	value = 1;
	field[0].num_bits = 1;
	field[0].out_value = &value;
	field[0].in_value = NULL;

	jtag_add_dr_scan(tap, 1, &field[0], TAP_DRSHIFT);

	crc_calc = 0xffffffff;
	for (i = 0; i < word_count; i++) {
		if (word_size_bytes == 4)
			datawords = ((uint32_t *)data)[i];
		else if (word_size_bytes == 2)
			datawords = ((uint16_t *)data)[i];
		else
			datawords = ((uint8_t *)data)[i];

		crc_calc = adbg_compute_crc(crc_calc, datawords, word_size_bits);
	}

	total_size_bytes = (word_count * word_size_bytes) + 4;
	total_size_32 = total_size_bytes / 4;
	spare_bytes = total_size_bytes % 4;

	out_buffer = malloc(total_size_bytes);

	memcpy(out_buffer, data, (word_count * word_size_bytes));
	memcpy(&out_buffer[(word_count * word_size_bytes)], &crc_calc, 4);

	for (i = 0;i < total_size_32; i++) {
		field[i].num_bits = 32;
		field[i].out_value = &out_buffer[i * 4];
		field[i].in_value = NULL;
		nb_fields++;
	}

	if (spare_bytes) {
		field[i].num_bits = spare_bytes * 8;
		field[i].out_value = &out_buffer[i * 4];
		field[i].in_value = NULL;
		nb_fields++;
	}

	jtag_add_dr_scan(tap, nb_fields, field, TAP_DRSHIFT);

	jtag_execute_queue();

	/* Read the 'CRC match' bit, and go to idle */
	field[0].num_bits = 1;
	field[0].out_value = NULL;
	field[0].in_value = &value;
	jtag_add_dr_scan(tap, 1, &field[0], TAP_IDLE);

	jtag_execute_queue();

	if (!value) {
		LOG_DEBUG("CRC ERROR! match bit after write is %i (computed CRC 0x%x)", value, crc_calc);
		if(retry_full_crc++ < MAX_WRITE_CRC_RETRY)
			goto retry_full_write;
		else {
			free(out_buffer);
			return ERROR_FAIL;
		}
	}
	else
		LOG_DEBUG("CRC OK!\n");

	/* Now, read the error register, and retry/recompute as necessary */
	if(or1k_jtag_module_selected == DC_WISHBONE) {
#ifndef MORE_SPEED_NO_CONTROL
		adbg_ctrl_read(jtag_info, DBG_WB_REG_ERROR, err_data, 1); /* First, just get 1 bit...read address only if necessary */
#endif
		if(err_data[0] & 0x1) { /* Then we have a problem */

			adbg_ctrl_read(jtag_info, DBG_WB_REG_ERROR, err_data, 33);
			addr = (err_data[0] >> 1) | (err_data[1] << 31);
			LOG_DEBUG("ERROR!  WB bus error during burst write, address 0x%X (index 0x%lX), retrying!", addr, (addr - start_address) / word_size_bytes);

			bus_error_retries++;
			if (bus_error_retries > MAX_BUS_ERRORS) {
				LOG_DEBUG("Max WB bus errors reached during burst read");
				return ERROR_FAIL;
			}

			/* Don't call retry_do(), a JTAG reset won't help a WB bus error */
			err_data[0] = 1;
			adbg_ctrl_write(jtag_info, DBG_WB_REG_ERROR, err_data, 1);  // Write 1 bit, to reset the error register,
			goto retry_full_write;
		}
	}

	free(out_buffer);

	return ERROR_OK;
}


/* Currently hard set in functions to 32-bits */
int or1k_jtag_read_cpu(struct or1k_jtag *jtag_info,
		       uint32_t addr, uint32_t *value)
{
	uint32_t read_value;

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_CPU0);
	adbg_wb_burst_read(jtag_info, 4, 1, addr, (void *)&read_value);

	h_u32_to_be((uint8_t*)value, read_value);

	return ERROR_OK;
}

int or1k_jtag_write_cpu(struct or1k_jtag *jtag_info,
			uint32_t addr, uint32_t value)
{
	uint32_t value_be;

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	h_u32_to_be((uint8_t*)&value_be, value);

	adbg_select_module(jtag_info, DC_CPU0);
	adbg_wb_burst_write(jtag_info, &value_be, 4, 1, addr);

	return ERROR_OK;
}


int or1k_jtag_read_cpu_cr(struct or1k_jtag *jtag_info,
			  uint32_t *value)
{
	uint32_t data;
	/*LOG_DEBUG("Reading CPU control register: ");*/

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_CPU0);
	adbg_ctrl_read(jtag_info, DBG_CPU0_REG_STATUS, &data, 2);

	/*LOG_DEBUG("cpu_cr = %08x", data);*/

	*value = 0;
	if (data & 1)
		*value |= OR1K_MOHORDBGIF_CPU_CR_STALL;

	if(data & 2)
		*value |= OR1K_MOHORDBGIF_CPU_CR_RESET;

	return ERROR_OK;
}

int or1k_jtag_write_cpu_cr(struct or1k_jtag *jtag_info,
			   uint32_t stall, uint32_t reset)
{
	uint32_t dataword = 0;

	dataword |= stall;
	dataword |= reset << 1;

	LOG_DEBUG("Writing CPU control register");

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_CPU0);
	adbg_ctrl_write(jtag_info, DBG_CPU0_REG_STATUS, &dataword, 2);

	return ERROR_OK;
}

int or1k_jtag_read_memory32(struct or1k_jtag *jtag_info,
			    uint32_t addr, int count, uint32_t *buffer)
{
	int i;

	LOG_DEBUG("Reading WB32 at 0x%08X", addr);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_WISHBONE);
	adbg_wb_burst_read(jtag_info, 4, count, addr, buffer);

	for(i= 0 ; i < count; i ++) {
		h_u32_to_be((uint8_t*) &buffer[i],buffer[i]);
	}


	return ERROR_OK;

}

int or1k_jtag_read_memory16(struct or1k_jtag *jtag_info,
			    uint32_t addr, int count, uint16_t *buffer)
{
	LOG_DEBUG("Reading WB16 at 0x%08X", addr);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_WISHBONE);
	adbg_wb_burst_read(jtag_info, 2, count, addr, buffer);

	return ERROR_OK;
}

int or1k_jtag_read_memory8(struct or1k_jtag *jtag_info,
			   uint32_t addr, int count, uint8_t *buffer)
{
	LOG_DEBUG("Reading WB8 at 0x%08X", addr);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_WISHBONE);
	adbg_wb_burst_read(jtag_info, 1, count, addr, buffer);

	return ERROR_OK;
}

int or1k_jtag_write_memory32(struct or1k_jtag *jtag_info,
			     uint32_t addr, int count, const uint32_t *buffer)
{
	int i;

	for(i= 0 ; i < count; i ++) {
		h_u32_to_be((uint8_t*) &buffer[i],buffer[i]);
	}

	LOG_DEBUG("Writing WB32 at 0x%08X = 0x%08X", addr, buffer[0]);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_WISHBONE);
	adbg_wb_burst_write(jtag_info, (void *)buffer, 4, count, addr);

	return ERROR_OK;

}

int or1k_jtag_write_memory16(struct or1k_jtag *jtag_info,
			     uint32_t addr, int count, const uint16_t *buffer)
{
	LOG_DEBUG("Writing WB16 at 0x%08X", addr);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_WISHBONE);
	adbg_wb_burst_write(jtag_info, (void *)buffer, 2, count, addr);

	return ERROR_OK;
}

int or1k_jtag_write_memory8(struct or1k_jtag *jtag_info,
			    uint32_t addr, int count, const uint8_t *buffer)
{
	LOG_DEBUG("Writing WB8 at 0x%08X", addr);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	adbg_select_module(jtag_info,DC_WISHBONE);
	adbg_wb_burst_write(jtag_info, (void *)buffer, 1, count, addr);

	return ERROR_OK;
}

int or1k_jtag_read_regs(struct or1k_jtag *jtag_info, uint32_t *regs)
{
	int i;

	/* read core registers */
	for (i = 0; i < OR1KNUMCOREREGS ; i++)
	{
		or1k_jtag_read_cpu(jtag_info,
				   /* or1k spr address is in second field of
				      or1k_core_reg_list_arch_info
				   */
				   or1k_core_reg_list_arch_info[i].spr_num,
				   regs + i);

		/* Switch endianness of data just read */
		h_u32_to_be((uint8_t*) &regs[i], regs[i]);

		LOG_DEBUG("Read cache reg %d: 0x%08x",i,regs[i]);
	}

	return ERROR_OK;
}

int or1k_jtag_write_regs(struct or1k_jtag *jtag_info, uint32_t *regs)
{
	int i;
	uint32_t regval_be;

	for (i = 0; i < OR1KNUMCOREREGS; i++)
	{
		LOG_DEBUG("Write cache reg %d: 0x%08x",i,regs[i]);

		/* Switch endianness of data before we write */
		h_u32_to_be((uint8_t*) &regval_be, regs[i]);

		or1k_jtag_write_cpu(jtag_info,
				    /* or1k spr address is in second field of
				       or1k_core_reg_list_arch_info
				    */
				    or1k_core_reg_list_arch_info[i].spr_num,
				    regval_be);
	}

	return ERROR_OK;
}

