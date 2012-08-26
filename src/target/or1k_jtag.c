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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "target.h"
#include "helper/types.h"
#include "jtag/jtag.h"
#include "or1k_jtag.h"
#include "or1k.h"


static int or1k_jtag_inited = 0;
static int or1k_jtag_module_selected = -1;

int or1k_jtag_init(struct or1k_jtag *jtag_info)
{

	LOG_DEBUG(" Initialising OpenCores JTAG TAP for Mohor Debug Interface"
		  );

	/* Put TAP into state where it can talk to the debug interface
	   by shifting in correct value to IR */
	struct jtag_tap *tap;

	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;


	struct scan_field field;
	uint8_t t[4];
	uint8_t ret[4];
      
	field.num_bits = tap->ir_length;
	field.out_value = t;
	/* OpenCores Mohor JTAG TAP-specific */
	buf_set_u32(t, 0, field.num_bits, OR1K_TAP_INST_DEBUG);
	field.in_value = ret;

	/* Ensure TAP is reset - maybe not necessary*/
	jtag_add_tlr();
      
	jtag_add_ir_scan(tap, &field, TAP_IDLE);
	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR(" setting TAP's IR to DEBUG failed");
		return ERROR_FAIL;
	}

	/* TAP should now be configured to communicate with debug interface */
	or1k_jtag_inited = 1;
	
	/* TAP reset - not sure what state debug module chain is in now */
	or1k_jtag_module_selected = -1;

	return ERROR_OK;

}

static uint32_t or1k_jtag_mohor_debug_crc_calc(uint32_t crc, 
					       uint32_t input_bit) 
{
	uint32_t d = (input_bit) ? 0xfffffff : 0x0000000;
	uint32_t crc_32 = ((crc >> 31)&1) ? 0xfffffff : 0x0000000;
	crc <<= 1;
#define OR1K_JTAG_MOHOR_DBG_CRC_POLY      0x04c11db7
	return crc ^ ((d ^ crc_32) & OR1K_JTAG_MOHOR_DBG_CRC_POLY);
}


int or1k_jtag_mohor_debug_select_module(struct or1k_jtag *jtag_info, 
					uint32_t module)
{
	int i;
	uint32_t out_module_select_bit, out_module,
		out_crc, in_crc, expected_in_crc, in_status;

	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	if (module > 15)
	{
		LOG_ERROR(" setting debug interface module failed (%d)" 
			  , module);
		return ERROR_FAIL;
	}


	/*
	 * CPU control register write
	 * Send:
	 * {1,4'moduleID,32'CRC,36'x           }
	 * Receive:
	 * {37'x               ,4'status,32'CRC}
	 */  
	struct scan_field fields[5];
  
	/* 1st bit is module select, set to '1' */
	out_module_select_bit = 1;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Module number */
	out_module = flip_u32(module,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_module;
	fields[1].in_value = NULL;

	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
						 out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_module>>i)&0x1));
	out_crc = flip_u32(out_crc,32);

	/* CRC going out */
	fields[2].num_bits = 32;
	fields[2].out_value = (uint8_t*) &out_crc;
	fields[2].in_value = NULL;

	/* Status coming in */
	fields[3].num_bits = 4;
	fields[3].out_value = NULL;
	fields[3].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[4].num_bits = 32;
	fields[4].out_value = NULL;
	fields[4].in_value = (uint8_t*) &in_crc;
  
	LOG_DEBUG(" setting mohor debug IF module: %d", module);

	jtag_add_dr_scan(tap, 5, fields, TAP_IDLE);

	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR(" performing module change failed" );
		return ERROR_FAIL;
	}

	/* Calculate expected CRC for status */
	expected_in_crc = 0xffffffff;
	for(i=0;i<4;i++)
		expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc,
								 ((in_status>>i)&
								  0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	expected_in_crc = flip_u32(expected_in_crc,32);

	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		return ERROR_FAIL;
	}
  
	if (in_status & OR1K_MOHORDBGIF_MODULE_SELECT_CRC_ERROR)
	{
		LOG_ERROR(" debug IF module select status: CRC error"
			  );
		return ERROR_FAIL;
	}
	else if (in_status & OR1K_MOHORDBGIF_MODULE_SELECT_MODULE_NOT_EXIST)
	{
		LOG_ERROR(" debug IF module select status: Invalid module (%d)"
			  , module);
		return ERROR_FAIL;
	}
	else if ((in_status & 0xf) == OR1K_MOHORDBGIF_MODULE_SELECT_OK)
	{
		LOG_DEBUG(" setting mohor debug IF OK");
		or1k_jtag_module_selected = module;
	}
	else
	{
		LOG_ERROR(" debug IF module select status: Unknown status (%x)"
			  , in_status & 0xf);
		return ERROR_FAIL;
	}


	return ERROR_OK;

}

int or1k_jtag_mohor_debug_set_command(struct or1k_jtag *jtag_info, 
				       uint32_t out_accesstype,
				       uint32_t out_address,
				       uint32_t out_length_bytes)
{
	LOG_DEBUG("Setting mohor debug command. TYPE:0x%01x ADR:0x%08x LEN:%d",
		  out_accesstype, out_address, out_length_bytes);

	
	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	/*
	 * Command register write
	 * Send:
	 * {1'0, 4'writecmd,4'type,32'address,16'len,32'crc,36'x
	 * Receive:
	 * {89'x                                           ,4'status, 32'CRC}
	 */
	struct scan_field fields[8];
	uint32_t out_module_select_bit, out_cmd, out_crc;
	uint32_t in_status, in_crc, expected_in_crc;
	int i;
  
	/* 1st bit is module select, set to '0', we're not selecting a module */
	out_module_select_bit = 0;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Instruction: write command register, 4-bits */
	out_cmd = flip_u32(OR1K_MOHORDBGIF_CPU_MODULE_CMD_WRITE,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_cmd;
	fields[1].in_value = NULL;
  
	/* 4-bit access type */
	out_accesstype = flip_u32(out_accesstype,4);
	fields[2].num_bits = 4;
	fields[2].out_value = (uint8_t*) &out_accesstype;
	fields[2].in_value = NULL;

	/*32-bit address */
	out_address = flip_u32(out_address,32);
	fields[3].num_bits = 32;
	fields[3].out_value = (uint8_t*) &out_address;
	fields[3].in_value = NULL;

	/*16-bit length */
	/* Subtract 1 off it, as module does length+1 accesses */
	out_length_bytes--;
	out_length_bytes = flip_u32(out_length_bytes,16);
	fields[4].num_bits = 16;
	fields[4].out_value = (uint8_t*) &out_length_bytes;
	fields[4].in_value = NULL;


	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
						 out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_cmd>>i)&0x1));
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_accesstype>>i)&
							  0x1));
	for(i=0;i<32;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_address>>i)&
							  0x1));
	for(i=0;i<16;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_length_bytes>>i)&
							  0x1));


	/* CRC going out */
	out_crc = flip_u32(out_crc,32);
	fields[5].num_bits = 32;
	fields[5].out_value = (uint8_t*) &out_crc;
	fields[5].in_value = NULL;

	/* Status coming in */
	fields[6].num_bits = 4;
	fields[6].out_value = NULL;
	fields[6].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[7].num_bits = 32;
	fields[7].out_value = NULL;
	fields[7].in_value = (uint8_t*) &in_crc;
  
	jtag_add_dr_scan(tap, 8, fields, TAP_IDLE);

	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR(" performing CPU CR write failed" );
		return ERROR_FAIL;
	}

	/* Calculate expected CRC for status */
	expected_in_crc = 0xffffffff;
	for(i=0;i<4;i++)
		expected_in_crc = 
			or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
						       ((in_status>>i)&0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	expected_in_crc = flip_u32(expected_in_crc,32);
	
	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		return ERROR_FAIL;
	}
  
	if (in_status & OR1K_MOHORDBGIF_CMD_CRC_ERROR)
	{
		LOG_ERROR(" debug IF CPU command write status: CRC error"
			  );
		return ERROR_FAIL;
	}
	else if ((in_status&0xff) == OR1K_MOHORDBGIF_CMD_OK)
	{
		/*LOG_DEBUG(" debug IF command write OK");*/
	}
	else
	{
		LOG_ERROR(" debug IF command write: Unknown status (%d)"
			  , in_status);
		return ERROR_FAIL;
	}

	return ERROR_OK;

}

int or1k_jtag_mohor_debug_single_read_go(struct or1k_jtag *jtag_info, 
					 int type_size_bytes,
					 int length,
					 uint8_t *data)
{
	LOG_DEBUG("Doing mohor debug read go for %d bytes",(type_size_bytes *
							    length));
	
	assert(type_size_bytes > 0);
	assert(type_size_bytes < 5);
	
	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	/*
	 * Debug GO
	 * Send:
	 * {1'0, 4'gocmd,32'crc, ((len-1)*8)+4+32'x                 }
	 * Receive:
	 * {37'x               , ((len-1)*8)'data, 4'status, 32'crc }
	 */

	/* Figure out how many data fields we'll need. At present just do 1
	   per byte, but in future, maybe figure out how we can do as many 
	   32-bit fields as possible - might speed things up? */
	int num_data_fields = length * type_size_bytes;
	LOG_DEBUG("Number of data fields: %d",num_data_fields);
	struct scan_field *fields = malloc(sizeof(struct scan_field) *
					   (num_data_fields + 5));	
		
	uint32_t out_module_select_bit, out_cmd, out_crc;
	uint32_t in_status =0, in_crc, expected_in_crc;
	int i,j;
  
	/* 1st bit is module select, set to '0', we're not selecting a module */
	out_module_select_bit = 0;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Instruction: go command , 4-bits */
	out_cmd = flip_u32(OR1K_MOHORDBGIF_CPU_MODULE_CMD_GO,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_cmd;
	fields[1].in_value = NULL;

	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
						 out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_cmd>>i)&0x1));

	/* CRC going out */
	out_crc = flip_u32(out_crc,32);
	fields[2].num_bits = 32;
	fields[2].out_value = (uint8_t*) &out_crc;
	fields[2].in_value = NULL;
	
	for(i=0;i< num_data_fields;i++)
	{
		fields[3+i].num_bits= 8;
		fields[3+i].out_value = NULL;
		fields[3+i].in_value = &data[i];
	}
	
	/* Status coming in */
	fields[3 + num_data_fields].num_bits = 4;
	fields[3 + num_data_fields].out_value = NULL;
	fields[3 + num_data_fields].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[3 + num_data_fields + 1].num_bits = 32;
	fields[3 + num_data_fields + 1].out_value = NULL;
	fields[3 + num_data_fields + 1].in_value = (uint8_t*) &in_crc;
  
	jtag_add_dr_scan(tap, 3 + num_data_fields + 2, fields, TAP_IDLE);


	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR("performing GO command failed");
		
		goto error_finish;
	}

	/* Calculate expected CRC for data and status */
	expected_in_crc = 0xffffffff;

	for(i=0;i<num_data_fields;i++)
	{
		/* Process received data byte at a time */
		/* Calculate CRC and bit-reverse data */
		for(j=0;j<8;j++)
			expected_in_crc = 
				or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
							       ((data[i]>>j)&
								0x1));
		
		data[i] = flip_u32((uint32_t)data[i],8);
		LOG_DEBUG("%02x",data[i]&0xff);
	}

	for(i=0;i<4;i++)
		expected_in_crc = 
			or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
						       ((in_status>>i)&0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	in_crc = flip_u32(in_crc,32);
	
	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		goto error_finish;
	}
  
	if (in_status & OR1K_MOHORDBGIF_CMD_CRC_ERROR)
	{
		LOG_ERROR(" debug IF go command status: CRC error");
		goto error_finish;
	}
	else if (in_status & OR1K_MOHORDBGIF_CMD_WB_ERROR)
	{
		LOG_ERROR(" debug IF go command status: Wishbone error");
		goto error_finish;
	}
	else if (in_status & OR1K_MOHORDBGIF_CMD_OURUN_ERROR)
	{
		LOG_ERROR(" debug IF go command status: Overrun/underrun error"
			);
		/*goto error_finish*/
	}
	else if ((in_status&0xf) == OR1K_MOHORDBGIF_CMD_OK)
	{
		/*LOG_DEBUG(" debug IF go command OK");*/
	}
	else
	{
		LOG_ERROR(" debug IF go command: Unknown status (%d)", 
			  in_status);
		goto error_finish;
	}
	
	/* Free fields*/
	free(fields);

	return ERROR_OK;

error_finish:
		
	/* Free fields*/
	free(fields);

	return ERROR_FAIL;


}

int or1k_jtag_mohor_debug_multiple_read_go(struct or1k_jtag *jtag_info, 
					   int type_size_bytes, int length,
					   uint8_t *data)
{
	LOG_DEBUG("Doing mohor debug read go for %d bytes",(type_size_bytes *
							    length));
	
	assert(type_size_bytes > 0);
	assert(type_size_bytes < 5);
	
	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	/*
	 * Debug GO
	 * Send:
	 * {1'0, 4'gocmd,32'crc, ((len-1)*8)+4+32'x                 }
	 * Receive:
	 * {37'x               , ((len-1)*8)'data, 4'status, 32'crc }
	 */

	/* Figure out how many data fields we'll need. At present just do 1
	   per byte, but in future, maybe figure out how we can do as many 
	   32-bit fields as possible - might speed things up? */
	int num_bytes = length * type_size_bytes;
	int num_32bit_fields = 0;
	/* Right now, only support word maths */
	assert(type_size_bytes==4);
	if (type_size_bytes==4)
	{
		num_32bit_fields = num_bytes/4;
	}
	
	int num_data_fields = num_32bit_fields;
	printf("num data fields:%d, num bytes: %d\n",
	       num_data_fields, num_bytes);
	assert ((num_32bit_fields*4)==num_bytes);

	

	LOG_DEBUG("Number of data fields: %d",num_data_fields);
	struct scan_field *fields = malloc(sizeof(struct scan_field) *
					   (num_32bit_fields + 5));	
		
	uint32_t out_module_select_bit, out_cmd, out_crc;
	uint32_t in_status =0, in_crc, expected_in_crc;
	int i,j;
  
	/* 1st bit is module select, set to '0', we're not selecting a module */
	out_module_select_bit = 0;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Instruction: go command , 4-bits */
	out_cmd = flip_u32(OR1K_MOHORDBGIF_CPU_MODULE_CMD_GO,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_cmd;
	fields[1].in_value = NULL;

	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
						 out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_cmd>>i)&0x1));

	/* CRC going out */
	out_crc = flip_u32(out_crc,32);
	fields[2].num_bits = 32;
	fields[2].out_value = (uint8_t*) &out_crc;
	fields[2].in_value = NULL;


	/* Execute this intro to the transfers */
	jtag_add_dr_scan(tap, 3, fields, TAP_DRPAUSE);
	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR("performing GO command failed");
		goto error_finish;
	}
	
	for(i=0;i< num_32bit_fields;i++)
	{
		fields[3+i].num_bits= 32;
		fields[3+i].out_value = NULL;
		fields[3+i].in_value = &data[i*4];

		/* Execute this intro to the transfers */
		jtag_add_dr_scan(tap, 1, 
				 &fields[3+i], 
				 TAP_DRPAUSE);
		if (jtag_execute_queue() != ERROR_OK)
		{
			LOG_ERROR("performing GO command failed");
			goto error_finish;
		}		
	}

	/* Status coming in */
	fields[3 + num_data_fields].num_bits = 4;
	fields[3 + num_data_fields].out_value = NULL;
	fields[3 + num_data_fields].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[3 + num_data_fields + 1].num_bits = 32;
	fields[3 + num_data_fields + 1].out_value = NULL;
	fields[3 + num_data_fields + 1].in_value = (uint8_t*) &in_crc;
	
	/* Execute the final bits */
	jtag_add_dr_scan(tap, 2, &fields[3 + num_data_fields], TAP_IDLE);

	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR("performing GO command failed");
		
		goto error_finish;
	}

	/* Calculate expected CRC for data and status */
	expected_in_crc = 0xffffffff;

	for(i=0;i<num_bytes;i++)
	{
		/* Process received data byte at a time */
		/* Calculate CRC and bit-reverse data */
		for(j=0;j<8;j++)
			expected_in_crc = 
				or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
							       ((data[i]>>j)&
								0x1));
		
		data[i] = flip_u32((uint32_t)data[i],8);
		LOG_DEBUG("%02x",data[i]&0xff);
	}

	for(i=0;i<4;i++)
		expected_in_crc = 
			or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
						       ((in_status>>i)&0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	in_crc = flip_u32(in_crc,32);
	
	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		goto error_finish;
	}
  
	if (in_status & OR1K_MOHORDBGIF_CMD_CRC_ERROR)
	{
		LOG_ERROR(" debug IF go command status: CRC error");
		goto error_finish;
	}
	else if (in_status & OR1K_MOHORDBGIF_CMD_WB_ERROR)
	{
		LOG_ERROR(" debug IF go command status: Wishbone error");
		goto error_finish;
	}
	else if (in_status & OR1K_MOHORDBGIF_CMD_OURUN_ERROR)
	{
		LOG_ERROR(" debug IF go command status: Overrun/underrun error"
			);
		/*goto error_finish*/
	}
	else if ((in_status&0xf) == OR1K_MOHORDBGIF_CMD_OK)
	{
		/*LOG_DEBUG(" debug IF go command OK");*/
	}
	else
	{
		LOG_ERROR(" debug IF go command: Unknown status (%d)", 
			  in_status);
		goto error_finish;
	}
	
	/* Free fields*/
	free(fields);

	return ERROR_OK;

error_finish:
		
	/* Free fields*/
	free(fields);

	return ERROR_FAIL;

}

int or1k_jtag_mohor_debug_read_go(struct or1k_jtag *jtag_info, 
				  int type_size_bytes,
				  int length,
				  uint8_t *data)
{
	if (length==1)
		return or1k_jtag_mohor_debug_single_read_go(jtag_info,
							    type_size_bytes,
							    length, data);
	else
		return or1k_jtag_mohor_debug_multiple_read_go(jtag_info,
							      type_size_bytes,
							      length, data);
}

int or1k_jtag_mohor_debug_write_go(struct or1k_jtag *jtag_info, 
				  int type_size_bytes,
				  int length,
				  uint8_t *data)
{
	LOG_DEBUG("Doing mohor debug write go for %d bytes",(type_size_bytes *
							    length));
	
	assert(type_size_bytes > 0);
	assert(type_size_bytes < 5);
	
	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	/*
	 * Debug GO for write
	 * Send:
	 * {1'0, 4'gocmd,((len-1)*8)'data,32'crc, 4+32'x           }
	 * Receive:
	 * {37+((len-1)*8)'x                    , 4'status, 32'crc }
	 */

	/* Figure out how many data fields we'll need. At present just do 1
	   per byte, but in future, maybe figure out how we can do as many 
	   32-bit fields as possible - might speed things up? */
	int length_bytes = length * type_size_bytes;
	int num_data32_fields = length_bytes / 4;
	int num_data8_fields = length_bytes % 4;
	int num_data_fields = num_data32_fields + num_data8_fields;

	LOG_DEBUG("Doing mohor debug write go, %d 32-bit fields, %d 8-bit",
		  num_data32_fields, num_data8_fields);

	struct scan_field *fields = malloc(sizeof(struct scan_field) *
					   (num_data_fields + 5));	
		
	uint32_t out_module_select_bit, out_cmd, out_crc;
	uint32_t in_status =0, in_crc, expected_in_crc;
	int i,j;
  
	/* 1st bit is module select, set to '0', we're not selecting a module */
	out_module_select_bit = 0;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Instruction: go command , 4-bits */
	out_cmd = flip_u32(OR1K_MOHORDBGIF_CPU_MODULE_CMD_GO,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_cmd;
	fields[1].in_value = NULL;

	for(i=0;i< num_data32_fields;i++)
	{
		fields[2+i].num_bits= 32;
		fields[2+i].out_value = &data[i*4];
		fields[2+i].in_value = NULL;
	}

	for(i=0;i< num_data8_fields;i++)
	{
		fields[2+num_data32_fields+i].num_bits= 8;
		fields[2+num_data32_fields+i].out_value = 
			&data[(num_data32_fields*4)+i];
		fields[2+num_data32_fields+i].in_value = NULL;
	}
	

	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
						 out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 
							 ((out_cmd>>i)&0x1));

	/*LOG_DEBUG("Debug GO Tx data:");*/
	for(i=0;i<length_bytes;i++)
	{
		LOG_DEBUG("%02x",data[i]&0xff);
		/* Process received data byte at a time */
		data[i] = flip_u32((uint32_t)data[i],8);
		/* Calculate CRC and bit-reverse data */
		for(j=0;j<8;j++)
			out_crc = 
				or1k_jtag_mohor_debug_crc_calc(out_crc, 
							       ((data[i]>>j)&
								0x1));
	}

	/* CRC going out */
	out_crc = flip_u32(out_crc,32);
	fields[2 + num_data_fields].num_bits = 32;
	fields[2 + num_data_fields].out_value = (uint8_t*) &out_crc;
	fields[2 + num_data_fields].in_value = NULL;
	
	/* Status coming in */
	fields[3 + num_data_fields].num_bits = 4;
	fields[3 + num_data_fields].out_value = NULL;
	fields[3 + num_data_fields].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[3 + num_data_fields + 1].num_bits = 32;
	fields[3 + num_data_fields + 1].out_value = NULL;
	fields[3 + num_data_fields + 1].in_value = (uint8_t*) &in_crc;
  
	jtag_add_dr_scan(tap, 3 + num_data_fields + 2, fields, TAP_IDLE);

	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR("performing GO command failed");
		
		/* Free fields*/
		free(fields);

		return ERROR_FAIL;
	}

	
	/* Free fields*/
	free(fields);

	/* Calculate expected CRC for data and status */
	expected_in_crc = 0xffffffff;


	for(i=0;i<4;i++)
		expected_in_crc = 
			or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
						       ((in_status>>i)&0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	in_crc = flip_u32(in_crc,32);
	
	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		return ERROR_FAIL;
	}
  
	if (in_status & OR1K_MOHORDBGIF_CMD_CRC_ERROR)
	{
		LOG_ERROR(" debug IF go command status: CRC error"
			  );
		return ERROR_FAIL;
	}
	else if ((in_status&0xff) == OR1K_MOHORDBGIF_CMD_OK)
	{
		/*LOG_DEBUG(" debug IF go command OK");*/
	}
	else
	{
		LOG_ERROR(" debug IF go command: Unknown status (%d)"
			  , in_status);
		return ERROR_FAIL;
	}

	return ERROR_OK;

}


/* Currently hard set in functions to 32-bits */
int or1k_jtag_read_cpu(struct or1k_jtag *jtag_info,
		       uint32_t addr, uint32_t *value)
{
  
	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_CPU0)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_CPU0);

	/* Set command register to read a single word */
	if (or1k_jtag_mohor_debug_set_command(jtag_info, 
					      OR1K_MOHORDBGIF_CPU_ACC_READ,
					      addr,
					      4) != ERROR_OK)
		return ERROR_FAIL;

	if (or1k_jtag_mohor_debug_read_go(jtag_info, 4, 1,(uint8_t *)value) !=
	    ERROR_OK)
		return ERROR_FAIL;

	return ERROR_OK;
}

int or1k_jtag_write_cpu(struct or1k_jtag *jtag_info,
			uint32_t addr, uint32_t value)
{
	LOG_DEBUG(" writing CPU reg 0x%x = 0x%x", addr, value);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_CPU0)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_CPU0
			);

	/* Set command register to write a single word */
	or1k_jtag_mohor_debug_set_command(jtag_info, 
					  OR1K_MOHORDBGIF_CPU_ACC_WRITE,
					  addr,
					  4);

	
	if (or1k_jtag_mohor_debug_write_go(jtag_info, 4, 1,
					   (uint8_t *)&value) != ERROR_OK)
		return ERROR_FAIL;

	return ERROR_OK;

}


int or1k_jtag_read_cpu_cr(struct or1k_jtag *jtag_info,
			  uint32_t *value)
{
	/*LOG_DEBUG(" reading CPU control reg");*/

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);
  
	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_CPU0)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_CPU0);

	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	/*
	 * CPU control register write
	 * Send:
	 * {1'0, 4'command, 32'CRC, (52+4+32)'x                             }
	 * Receive:
	 * {37'x                  , 1'reset, 1'stall, 50'x, 4'status, 32'CRC}
	 */
	struct scan_field fields[9];
	uint32_t out_module_select_bit, out_cmd, out_crc;
	uint32_t in_status, in_crc, expected_in_crc, in_reset = 0, in_stall = 0,
		in_zeroes0, in_zeroes1;
	int i;

	/* 1st bit is module select, set to '0', we're not selecting a module */
	out_module_select_bit = 0;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Command, 4-bits */
	out_cmd = flip_u32(OR1K_MOHORDBGIF_CPU_MODULE_CMD_CTRL_READ,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_cmd;
	fields[1].in_value = NULL;

	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, ((out_cmd>>i)&0x1));
	out_crc = flip_u32(out_crc,32);

	/* CRC going out */
	fields[2].num_bits = 32;
	fields[2].out_value = (uint8_t*) &out_crc;
	fields[2].in_value = NULL;

  
	/* 52-bit control register */
	fields[3].num_bits = 1;
	fields[3].out_value = NULL;
	fields[3].in_value = (uint8_t*) &in_reset;

	fields[4].num_bits = 1;
	fields[4].out_value = NULL;
	fields[4].in_value = (uint8_t*) &in_stall;

	/* Assuming the next 50 bits will always be 0 */
	fields[5].num_bits = 32;
	fields[5].out_value = NULL;
	fields[5].in_value = (uint8_t*) &in_zeroes0;

	fields[6].num_bits = 18;
	fields[6].out_value = NULL;
	fields[6].in_value = (uint8_t*) &in_zeroes1;
  
	/* Status coming in */
	fields[7].num_bits = 4;
	fields[7].out_value = NULL;
	fields[7].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[8].num_bits = 32;
	fields[8].out_value = NULL;
	fields[8].in_value = (uint8_t*) &in_crc;
  
	jtag_add_dr_scan(tap, 9, fields, TAP_IDLE);

	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR(" performing CPU CR read failed" );
		return ERROR_FAIL;
	}

	/*
	  LOG_DEBUG("in_zeroes0: 0x%08x, in_zeroes1: 0x%08x",in_zeroes0,
	  in_zeroes1 & 0x3ffff);
	*/

	/* Calculate expected CRC for status */
	expected_in_crc = 0xffffffff;
	expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc, in_reset);
	expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc, in_stall);
	/* Assuming next 50 bits are zero - we don't check, though!*/
	for(i=0;i<32;i++)
		expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
								 ((in_zeroes0>>i)&0x1));
	for(i=0;i<18;i++)
		expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
								 ((in_zeroes1>>i)&0x1));
	for(i=0;i<4;i++)
		expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
								 ((in_status>>i)&0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	expected_in_crc = flip_u32(expected_in_crc,32);

	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		return ERROR_FAIL;
	}
  
	if (in_status & OR1K_MOHORDBGIF_CMD_CRC_ERROR)
	{
		LOG_ERROR(" debug IF CPU CR read status: CRC error");
		return ERROR_FAIL;
	}
	else if ((in_status&0xf) == OR1K_MOHORDBGIF_CMD_OK)
	{
		/*LOG_DEBUG(" debug IF CPU CR read OK");*/
	}
	else
	{
		LOG_ERROR(" debug IF CPU CR read: Unknown status (%d)"
			  , in_status);
		return ERROR_FAIL;
	}

	/* Convey status of control register */
	*value = 0;
  
	/*
	LOG_DEBUG("CPU CR reset bit: %0x",in_reset & 0x1);
	LOG_DEBUG("CPU CR stall bit: %0x",in_stall & 0x1);
	*/

	if (in_reset & 0x1)
		*value |= OR1K_MOHORDBGIF_CPU_CR_RESET;
    
  
	if (in_stall & 0x1)
	{
		*value |= OR1K_MOHORDBGIF_CPU_CR_STALL;
	}

	return ERROR_OK;
}

int or1k_jtag_write_cpu_cr(struct or1k_jtag *jtag_info,
			   uint32_t stall, uint32_t reset)
{

	LOG_DEBUG(" writing CPU control reg, reset: %d, stall: %d", 
		  reset, stall);

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_CPU0)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_CPU0);

      
	struct jtag_tap *tap;
  
	tap = jtag_info->tap;
	if (tap == NULL)
		return ERROR_FAIL;   

	/*
	 * CPU control register write
	 * Send:
	 * {1'0, 4'command, 1'reset, 1'stall, 50'0, 32'CRC, 36'x            }
	 * Receive:
	 * {89'x                                          , 4'status, 32'CRC}
	 */
	struct scan_field fields[9];
	uint32_t out_module_select_bit, out_cmd, out_crc;
	uint32_t in_status, in_crc, expected_in_crc;
	int i;
  
	/* 1st bit is module select, set to '0', we're not selecting a module */
	out_module_select_bit = 0;

	fields[0].num_bits = 1;
	fields[0].out_value = (uint8_t*) &out_module_select_bit;
	fields[0].in_value = NULL;

	/* Command, 4-bits */
	out_cmd = flip_u32(OR1K_MOHORDBGIF_CPU_MODULE_CMD_CTRL_WRITE,4);
	fields[1].num_bits = 4;
	fields[1].out_value = (uint8_t*) &out_cmd;
	fields[1].in_value = NULL;
  
	/* 52-bit control register */
	fields[2].num_bits = 1;
	fields[2].out_value = (uint8_t*) &reset;
	fields[2].in_value = NULL;

	fields[3].num_bits = 1;
	fields[3].out_value = (uint8_t*) &stall;
	fields[3].in_value = NULL;

	fields[4].num_bits = 32;
	fields[4].out_value = NULL;
	fields[4].in_value = NULL;

	fields[5].num_bits = 18;
	fields[5].out_value = NULL;
	fields[5].in_value = NULL;

	/* CRC calculations */
	out_crc = 0xffffffff;
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, out_module_select_bit);
	for(i=0;i<4;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, ((out_cmd>>i)&0x1));
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, reset);
	out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, stall);
	for(i=0;i<50;i++)
		out_crc = or1k_jtag_mohor_debug_crc_calc(out_crc, 0);
	out_crc = flip_u32(out_crc,32);

	/* CRC going out */
	fields[6].num_bits = 32;
	fields[6].out_value = (uint8_t*) &out_crc;
	fields[6].in_value = NULL;

	/* Status coming in */
	fields[7].num_bits = 4;
	fields[7].out_value = NULL;
	fields[7].in_value = (uint8_t*) &in_status;

	/* CRC coming in */
	fields[8].num_bits = 32;
	fields[8].out_value = NULL;
	fields[8].in_value = (uint8_t*) &in_crc;
  
	jtag_add_dr_scan(tap, 9, fields, TAP_IDLE);

	if (jtag_execute_queue() != ERROR_OK)
	{
		LOG_ERROR(" performing CPU CR write failed" );
		return ERROR_FAIL;
	}

	/* Calculate expected CRC for status */
	expected_in_crc = 0xffffffff;
	for(i=0;i<4;i++)
		expected_in_crc = or1k_jtag_mohor_debug_crc_calc(expected_in_crc, 
								 ((in_status>>i)&0x1));
	/* Check CRCs now */
	/* Bit reverse received CRC */
	expected_in_crc = flip_u32(expected_in_crc,32);

	if (in_crc != expected_in_crc)
	{
		LOG_ERROR(" received CRC (0x%08x) not same as calculated CRC (0x%08x)"
			  , in_crc, expected_in_crc);
		return ERROR_FAIL;
	}
  
	if (in_status & OR1K_MOHORDBGIF_CMD_CRC_ERROR)
	{
		LOG_ERROR(" debug IF CPU CR write status: CRC error");
		return ERROR_FAIL;
	}
	else if ((in_status&0xff) == OR1K_MOHORDBGIF_CMD_OK)
	{
		LOG_DEBUG(" debug IF CPU CR write OK");
	}
	else
	{
		LOG_ERROR(" debug IF module select status: Unknown status (%d)"
			  , in_status);
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

int or1k_jtag_read_memory32(struct or1k_jtag *jtag_info, 
			    uint32_t addr, int count, uint32_t *buffer)
{
	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_WB)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_WB);

	/* Set command register to read a single word */
	if (or1k_jtag_mohor_debug_set_command(jtag_info, 
					      OR1K_MOHORDBGIF_WB_ACC_READ32,
					      addr,
					      count*4) != ERROR_OK)
		return ERROR_FAIL;

	if (or1k_jtag_mohor_debug_read_go(jtag_info, 4, count,(uint8_t *)buffer)
	    != ERROR_OK)
		return ERROR_FAIL;

	return ERROR_OK;

}

int or1k_jtag_read_memory16(struct or1k_jtag *jtag_info, 
			    uint32_t addr, int count, uint16_t *buffer)
{
	/* TODO - this function! */
	return ERROR_OK;
}

int or1k_jtag_read_memory8(struct or1k_jtag *jtag_info, 
			   uint32_t addr, int count, uint8_t *buffer)
{
	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_WB)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_WB);
	
	/* At the moment, old Mohor can't read multiple bytes */
	while (count)
	{
		/* Set command register to read a single byte */
		if (or1k_jtag_mohor_debug_set_command(jtag_info, 
						      OR1K_MOHORDBGIF_WB_ACC_READ8,
						      addr,
						      1) != ERROR_OK)
			return ERROR_FAIL;

		if (or1k_jtag_mohor_debug_read_go(jtag_info, 1, 1,(uint8_t *)buffer)
		    != ERROR_OK)
			return ERROR_FAIL;

		count--;
		buffer++;
	}

	return ERROR_OK;
}

int or1k_jtag_write_memory32(struct or1k_jtag *jtag_info, 
			     uint32_t addr, int count, const uint32_t *buffer)
{

	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_WB)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_WB);

	/* Set command register to read a single word */
	if (or1k_jtag_mohor_debug_set_command(jtag_info, 
					      OR1K_MOHORDBGIF_WB_ACC_WRITE32,
					      addr,
					      count*4) != ERROR_OK)
		return ERROR_FAIL;

	if (or1k_jtag_mohor_debug_write_go(jtag_info, 4, count,(uint8_t *)buffer)
	    != ERROR_OK)
		return ERROR_FAIL;

	return ERROR_OK;

}

int or1k_jtag_write_memory16(struct or1k_jtag *jtag_info, 
			     uint32_t addr, int count, const uint16_t *buffer)
{
	/* TODO - this function! */
	return ERROR_OK;
}

int or1k_jtag_write_memory8(struct or1k_jtag *jtag_info, 
			    uint32_t addr, int count, const uint8_t *buffer)
{
	if (!or1k_jtag_inited)
		or1k_jtag_init(jtag_info);

	if (or1k_jtag_module_selected != OR1K_MOHORDBGIF_MODULE_WB)
		or1k_jtag_mohor_debug_select_module(jtag_info, 
						    OR1K_MOHORDBGIF_MODULE_WB);

	/* Set command register to read a single word */
	if (or1k_jtag_mohor_debug_set_command(jtag_info, 
					      OR1K_MOHORDBGIF_WB_ACC_WRITE32,
					      addr, count) != ERROR_OK)
		return ERROR_FAIL;
	
	if (or1k_jtag_mohor_debug_write_go(jtag_info, 1, count,(uint8_t *)buffer)
	    != ERROR_OK)
		return ERROR_FAIL;
	
	return ERROR_OK;
}

int or1k_jtag_read_regs(struct or1k_jtag *jtag_info, uint32_t *regs)
{
	int i;

	LOG_DEBUG(" - ");

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
		LOG_DEBUG("read cache reg %d: 0x%08x",i,regs[i]);
	}
	
	return ERROR_OK;
}

int or1k_jtag_write_regs(struct or1k_jtag *jtag_info, uint32_t *regs)
{
	int i;
	uint32_t regval_be;
	
	LOG_DEBUG(" - ");

	for (i = 0; i < OR1KNUMCOREREGS; i++) 
	{
		LOG_DEBUG("write cache reg %d: 0x%08x",i,regs[i]);
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

