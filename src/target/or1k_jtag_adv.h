#ifndef _ADV_DBG_COMMANDS_H_
#define _ADV_DBG_COMMANDS_H_


// Definitions for the top-level debug unit.  This really just consists
// of a single register, used to select the active debug module ("chain").
#define DBG_MODULE_SELECT_REG_SIZE 2
#define DBG_MAX_MODULES 4  // used to size an array

#define DC_WISHBONE 0
#define DC_CPU0     1
#define DC_CPU1     2
#define DC_JSP      3

// Polynomial for the CRC calculation
// Yes, it's backwards.  Yes, this is on purpose.
// The hardware is designed this way to save on logic and routing,
// and it's really all the same to us here.
#define ADBG_CRC_POLY 0xedb88320

// These are for the internal registers in the Wishbone module
// The first is the length of the index register,
// the indexes of the various registers are defined after that
#define DBG_WB_REG_SEL_LEN 1
#define DBG_WB_REG_ERROR 0

// Opcode definitions for the Wishbone module
#define DBG_WB_OPCODE_LEN   4
#define DBG_WB_CMD_NOP      0x0
#define DBG_WB_CMD_BWRITE8  0x1
#define DBG_WB_CMD_BWRITE16 0x2
#define DBG_WB_CMD_BWRITE32 0x3
#define DBG_WB_CMD_BREAD8   0x5
#define DBG_WB_CMD_BREAD16  0x6
#define DBG_WB_CMD_BREAD32  0x7
#define DBG_WB_CMD_IREG_WR  0x9  // This is both a select and a write
#define DBG_WB_CMD_IREG_SEL 0xd  // There is no 'read', the current register is always read.  Use a NOP to read.


// Internal register definitions for the CPU0 module
#define DBG_CPU0_REG_SEL_LEN 1
#define DBG_CPU0_REG_STATUS 0

// Opcode definitions for the first CPU module
#define DBG_CPU0_OPCODE_LEN   4
#define DBG_CPU0_CMD_NOP      0x0
#define DBG_CPU0_CMD_BWRITE32 0x3
#define DBG_CPU0_CMD_BREAD32  0x7
#define DBG_CPU0_CMD_IREG_WR  0x9  // This is both a select and a write
#define DBG_CPU0_CMD_IREG_SEL 0xd  // There is no 'read', the current register is always read.  Use a NOP to read.

// Internal register definitions for the CPU1 module
#define DBG_CPU1_REG_SEL_LEN 1
#define DBG_CPU1_REG_STATUS 0

// Opcode definitions for the second CPU module
#define DBG_CPU1_OPCODE_LEN   4
#define DBG_CPU1_CMD_NOP      0x0
#define DBG_CPU1_CMD_BWRITE32 0x3
#define DBG_CPU1_CMD_BREAD32  0x7
#define DBG_CPU1_CMD_IREG_WR  0x9  // This is both a select and a write
#define DBG_CPU1_CMD_IREG_SEL 0xd  // There is no 'read', the current register is always read.  Use a NOP to read.

#endif
