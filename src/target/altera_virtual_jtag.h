#ifndef _ALTERA_VIRTUAL_JTAG_H_
#define _ALTERA_VIRTUAL_JTAG_H_

// Contains constants relevant to the Altera Virtual JTAG
// device, which are not included in the BSDL.
// As of this writing, these are constant across every
// device which supports virtual JTAG.

// These are commands for the FPGA's IR
#define ALTERA_CYCLONE_CMD_VIR     0x0E
#define ALTERA_CYCLONE_CMD_VDR     0x0C

// These defines are for the virtual IR (not the FPGA's)
// The virtual TAP was defined in hardware to match the OpenCores native
// TAP in both IR size and DEBUG command.
#define ALT_VJTAG_IR_SIZE    4
#define ALT_VJTAG_CMD_DEBUG  0x8

// SLD node ID
#define JTAG_TO_AVALON_NODE_ID	0x84
#define VJTAG_NODE_ID		0x08
#define SIGNAL_TAP_NODE_ID	0x00

union hub_info {
	struct {
		unsigned m_width :8;
		unsigned manufacturer_id :11;
		unsigned nb_of_node :8;
		unsigned version :5;
	};
	uint32_t dword;
};

union node_info {
	struct {
		unsigned instance_id :8;
		unsigned manufacturer_id :11;
		unsigned node_id :8;
		unsigned version :5;
	};
	uint32_t dword;
};

#endif
