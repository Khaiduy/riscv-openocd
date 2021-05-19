/***************************************************************************
 *   Copyright (C) 2009 Zachary T Welch <zw@superlucidity.net>             *
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
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/log.h>

#include "target.h"
#include "target_type.h"
#include "hello.h"
#include "riscv/riscv.h"
#include "register.h"
#include "mips_ejtag.h"
#include "riscv/debug_defines.h"

struct target;

#define OPEN8_COMMON_MAGIC	0x01
#define OPEN8_NUM_CORE_REGS 9

#define OPEN8_SCAN_DELAY_LEGACY_MODE 2000000

struct open8_common {
	uint32_t common_magic;
	void *arch_info;
	struct reg_cache *core_cache;
	uint32_t core_regs[OPEN8_NUM_CORE_REGS];
	struct mips_ejtag ejtag_info;

	/* register cache to processor synchronization */
	int (*read_core_reg)(struct target *target, unsigned int num);
	int (*write_core_reg)(struct target *target, unsigned int num);
};

static inline struct open8_common *
target_to_open8(struct target *target)
{
	return target->arch_info;
}

struct open8_core_reg {
	uint32_t num;
	struct target *target;
	struct open8_common *open8_common;
};

uint8_t ir_idcode[4] = {0x01};
struct scan_field select_idcode_open8 = {
	.in_value = NULL,
	.out_value = ir_idcode
};
static struct reg_cache *open8_build_reg_cache(struct target *target);
static const struct {
	unsigned id;
	const char *name;
	const uint8_t bits;
	enum reg_type type;
	const char *group;
	const char *feature;
	int flag;
} open8_regs[] = {
	{  0,  "r0", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  1,  "r1", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  2,  "r2", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  3,  "r3", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  4,  "r4", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  5,  "r5", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  6,  "r6", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  7,  "r7", 8, REG_TYPE_UINT8, "general", "org.gnu.gdb.open8.core", 0 },
	{  8,  "pc", 16, REG_TYPE_UINT16, "general", "org.gnu.gdb.open8.core", 0 },
};

#define OPEN8_NUM_REGS ARRAY_SIZE(open8_regs)

#define OPEN8_R0 0
#define OPEN8_R1 1
#define OPEN8_R2 2
#define OPEN8_R3 3
#define OPEN8_R4 4
#define OPEN8_R5 5
#define OPEN8_R6 6
#define OPEN8_R7 7
#define OPEN8_PC 8


static const struct command_registration testee_command_handlers[] = {
	{
		.name = "testee",
		.mode = COMMAND_ANY,
		.help = "testee target commands",
		.chain = hello_command_handlers,
		.usage = "",
	},
	COMMAND_REGISTRATION_DONE
};

uint32_t open8_read_dmi(struct mips_ejtag *ejtag_info, uint32_t address)
{
	assert(ejtag_info->tap != NULL);
	struct jtag_tap *tap = ejtag_info->tap;

	unsigned num_bits = 7 + DTM_DMI_OP_LENGTH + DTM_DMI_DATA_LENGTH;
	size_t num_bytes = (num_bits + 7) / 8;
	uint8_t in[num_bytes];
	uint8_t out[num_bytes];
	struct scan_field field = {
		.num_bits = num_bits,
		.out_value = out,
		.in_value = in
	};
	memset(in, 0, num_bytes);
	memset(out, 0, num_bytes);

	mips_ejtag_set_instr(ejtag_info, 0x11);
	buf_set_u32(out, DTM_DMI_OP_OFFSET, DTM_DMI_OP_LENGTH, 1);
	buf_set_u32(out, DTM_DMI_DATA_OFFSET, DTM_DMI_DATA_LENGTH, 0);
	buf_set_u32(out, DTM_DMI_ADDRESS_OFFSET, 7, address);

	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
    jtag_add_runtest(50, TAP_IDLE);
	int retval = jtag_execute_queue();	
	if (retval != ERROR_OK) {
		LOG_ERROR("read dmi failed jtag scan");
	}
    /*keep_alive();


	mips_ejtag_set_instr(ejtag_info, 0x11);
	buf_set_u32(out, DTM_DMI_OP_OFFSET, DTM_DMI_OP_LENGTH, 0);
	buf_set_u32(out, DTM_DMI_DATA_OFFSET, DTM_DMI_DATA_LENGTHuint32_t retval = open8_read_dmi(ejtag_info, 0x11);

	retval = jtag_execute_queue();	
	if (retval != ERROR_OK) {
		LOG_ERROR("read dmi failed jtag scan");
	}*/
    keep_alive();
	mips_ejtag_set_instr(ejtag_info, 0x11);
	
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
	retval = jtag_execute_queue();	
	if (retval != ERROR_OK) {
		LOG_ERROR("read dmi failed jtag scan");
	}
	keep_alive();
	return buf_get_u32(in, DTM_DMI_DATA_OFFSET, DTM_DMI_DATA_LENGTH);
}


void open8_write_dmi(struct mips_ejtag *ejtag_info, uint32_t address, uint32_t data)
{
	assert(ejtag_info->tap != NULL);
	struct jtag_tap *tap = ejtag_info->tap;

	unsigned num_bits = 7 + DTM_DMI_OP_LENGTH + DTM_DMI_DATA_LENGTH;
	size_t num_bytes = (num_bits + 7) / 8;
	uint8_t in[num_bytes];
	uint8_t out[num_bytes];
	struct scan_field field = {
		.num_bits = num_bits,
		.out_value = out,
		.in_value = in
	};
	memset(in, 0, num_bytes);
	memset(out, 0, num_bytes);

	mips_ejtag_set_instr(ejtag_info, 0x11);
	buf_set_u32(out, DTM_DMI_OP_OFFSET, DTM_DMI_OP_LENGTH, 2);
	buf_set_u32(out, DTM_DMI_DATA_OFFSET, DTM_DMI_DATA_LENGTH, data);
	buf_set_u32(out, DTM_DMI_ADDRESS_OFFSET, 7, address);

	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
    jtag_add_runtest(50, TAP_IDLE);
	int retval = jtag_execute_queue();
	if (retval != ERROR_OK) {
		LOG_ERROR("write dmi failed jtag scan");
	}
	keep_alive();
}
void open8_bypass(struct mips_ejtag *ejtag_info)
{
	/*assert(ejtag_info->tap != NULL);
	struct jtag_tap *tap = ejtag_info->tap;

	uint8_t scan_out[4] = { 0 };

	struct scan_field field;
	field.num_bits = 32;
	field.out_value = scan_out;*/
	mips_ejtag_set_instr(ejtag_info, 0x1f);
	/*buf_set_u32(scan_out, 0, 1, 0);

	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
    jtag_add_runtest(10, TAP_IDLE);
	int retval = jtag_execute_queue();	
	if (retval != ERROR_OK) {
		LOG_ERROR("read dmi failed jtag scan");
	}
    keep_alive();*/
	uint32_t retval = 0;
	mips_ejtag_drscan_32(ejtag_info, &retval);
}
static int open8_read_core_reg(struct target *target, unsigned int num)
{
	uint32_t reg_value;

	/* get pointers to arch-specific information */
	struct open8_common *open8 = target_to_open8(target);

	if (num >= OPEN8_NUM_REGS)
		return ERROR_COMMAND_SYNTAX_ERROR;

	reg_value = open8->core_regs[num];
	LOG_DEBUG("read core reg %i value 0x%" PRIx32 "", num, reg_value);
	buf_set_u32(open8->core_cache->reg_list[num].value, 0, 32, reg_value);
	open8->core_cache->reg_list[num].valid = true;
	open8->core_cache->reg_list[num].dirty = false;

	return ERROR_OK;
}

static int open8_write_core_reg(struct target *target, unsigned int num)
{
	uint32_t reg_value;

	/* get pointers to arch-specific information */
	struct open8_common *open8 = target_to_open8(target);

	if (num >= OPEN8_NUM_REGS)
		return ERROR_COMMAND_SYNTAX_ERROR;

	reg_value = buf_get_u32(open8->core_cache->reg_list[num].value, 0, 32);
	open8->core_regs[num] = reg_value;
	LOG_DEBUG("write core reg %i value 0x%" PRIx16 "", num, reg_value);
	open8->core_cache->reg_list[num].valid = true;
	open8->core_cache->reg_list[num].dirty = false;

	return ERROR_OK;
}

static int open8_init_arch_info(struct target *target,
		struct open8_common *open8, struct jtag_tap *tap)
{
	target->endianness = TARGET_BIG_ENDIAN;
	target->arch_info = open8;
	open8->common_magic = OPEN8_COMMON_MAGIC;

	open8->ejtag_info.tap = tap;
	/* if unknown endianness defaults to little endian, 1 */
	open8->ejtag_info.endianness = target->endianness == TARGET_BIG_ENDIAN ? 0 : 1;
	open8->ejtag_info.scan_delay = OPEN8_SCAN_DELAY_LEGACY_MODE;
	open8->ejtag_info.mode = 0;			/* Initial default value */
	open8->ejtag_info.isa = 0;	/* isa on debug mips32, updated by poll function */
	open8->ejtag_info.config_regs = 0;	/* no config register read */

	open8->read_core_reg = open8_read_core_reg;
	open8->write_core_reg = open8_write_core_reg;

	/*stm8_init_flash_regs(0, stm8);*/

	return ERROR_OK;
}

static int open8_target_create(struct target *target,
		Jim_Interp *interp)
{

	struct open8_common *open8 = calloc(1, sizeof(struct open8_common));

	open8_init_arch_info(target, open8, target->tap);
	//stm8_configure_break_unit(target);
	LOG_DEBUG("In target_create now!!");
	return ERROR_OK;
}
static int open8_get_core_reg(struct reg *reg)
{
	int retval;
	struct open8_core_reg *open8_reg = reg->arch_info;
	struct target *target = open8_reg->target;
	struct open8_common *open8_target = target_to_open8(target);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	retval = open8_target->read_core_reg(target, open8_reg->num);

	return retval;
}

static int open8_set_core_reg(struct reg *reg, uint8_t *buf)
{
	struct open8_core_reg *open8_reg = reg->arch_info;
	struct target *target = open8_reg->target;
	uint32_t value = buf_get_u32(buf, 0, reg->size);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	buf_set_u32(reg->value, 0, 32, value);
	reg->dirty = true;
	reg->valid = true;

	return ERROR_OK;
}


static const struct reg_arch_type open8_reg_type = {
	.get = open8_get_core_reg,
	.set = open8_set_core_reg,
};


static struct reg_cache *open8_build_reg_cache(struct target *target)
{
	/* get pointers to arch-specific information */
	struct open8_common *open8 = target_to_open8(target);

	int num_regs = OPEN8_NUM_REGS;
	struct reg_cache **cache_p = register_get_last_cache_p(&target->reg_cache);
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	struct reg *reg_list = calloc(num_regs, sizeof(struct reg));
	struct open8_core_reg *arch_info = malloc(
			sizeof(struct open8_core_reg) * num_regs);
	struct reg_feature *feature;
	int i;

	/* Build the process context cache */
	cache->name = "open8 registers";
	cache->next = NULL;
	cache->reg_list = reg_list;
	cache->num_regs = num_regs;
	(*cache_p) = cache;
	open8->core_cache = cache;

	for (i = 0; i < num_regs; i++) {
		arch_info[i].num = open8_regs[i].id;
		arch_info[i].target = target;
		arch_info[i].open8_common = open8;

		reg_list[i].name = open8_regs[i].name;
		reg_list[i].size = open8_regs[i].bits;

		reg_list[i].value = calloc(1, 4);
		reg_list[i].valid = false;
		reg_list[i].type = &open8_reg_type;
		reg_list[i].arch_info = &arch_info[i];

		reg_list[i].reg_data_type = calloc(1, sizeof(struct reg_data_type));
		if (reg_list[i].reg_data_type)
			reg_list[i].reg_data_type->type = open8_regs[i].type;
		else {
			LOG_ERROR("unable to allocate reg type list");
			return NULL;
		}

		reg_list[i].dirty = false;
		reg_list[i].group = open8_regs[i].group;
		reg_list[i].number = open8_regs[i].id;
		reg_list[i].exist = true;
		reg_list[i].caller_save = true;	/* gdb defaults to true */

		feature = calloc(1, sizeof(struct reg_feature));
		if (feature) {
			feature->name = open8_regs[i].feature;
			reg_list[i].feature = feature;
		} else
			LOG_ERROR("unable to allocate feature list");
	}

	return cache;
}
static int open8_examine(struct target *target)
{
	struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;
	int retval = mips_ejtag_init(ejtag_info);
	if (retval != ERROR_OK)
		return retval;

	if (!target_was_examined(target)) {
		target_set_examined(target);
		return ERROR_OK;
	}

	return ERROR_OK;
}
static int open8_init(struct command_context *cmd_ctx, struct target *target)
{

	open8_build_reg_cache(target);

	return ERROR_OK;
}

static int open8_get_gdb_reg_list(struct target *target, struct reg **reg_list[],
		int *reg_list_size, enum target_register_class reg_class)
{
	/* get pointers to arch-specific information */
	struct open8_common *open8 = target_to_open8(target);
	unsigned int i;

	*reg_list_size = OPEN8_NUM_REGS;
	*reg_list = malloc(sizeof(struct reg *) * (*reg_list_size));

	for (i = 0; i < OPEN8_NUM_REGS; i++)
		(*reg_list)[i] = &open8->core_cache->reg_list[i];

	return ERROR_OK;
}

static int open8_read_regs(struct target *target, uint32_t regs[])
{
	struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;
    uint32_t R0 = open8_read_dmi(ejtag_info, 0x04);
	open8_bypass(ejtag_info);
	uint32_t R1 = open8_read_dmi(ejtag_info, 0x05);
	open8_bypass(ejtag_info);
	for(unsigned int i = 0; i < OPEN8_NUM_REGS - 1; i++){
		int reg_value;
		if(i <= 3){
			reg_value = ((R0 >> (8 * i)) & 0xff);
			
		}
		else {
			reg_value = ((R1 >> (8 * (i - 4))) & 0xff);
		}
		regs[i] = reg_value;
	}
	uint32_t R2 = open8_read_dmi(ejtag_info, 0x06);
	open8_bypass(ejtag_info);
	regs[OPEN8_PC] = R2 & 0xFFFF;

	return ERROR_OK;
}

static int open8_write_regs(struct target *target, uint32_t regs[])
{
    struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;
    /*uint32_t R0 = open8_read_dmi(ejtag_info, 0x04);
	open8_bypass(ejtag_info);
	uint32_t R1 = open8_read_dmi(ejtag_info, 0x05);
	open8_bypass(ejtag_info);*/
	uint32_t temp_1 = 0;
	uint32_t temp_2 = 0;

	for(unsigned int i = 0; i < OPEN8_NUM_REGS - 1; i++){
		if(i <= 3){
			temp_1 = (temp_1 & ~(0xff << (i * 8))) | ((regs[i] & 0xff) << (i * 8));
            open8_write_dmi(ejtag_info, 0x04, temp_1);
	        open8_bypass(ejtag_info);
		}
		else {
			temp_2 = (temp_2 & ~(0xff << ((i - 4) * 8))) | ((regs[i] & 0xff) << ((i - 4) * 8));
			open8_write_dmi(ejtag_info, 0x05, temp_2);
	        open8_bypass(ejtag_info);
		}
	}
    
	
	return ERROR_OK;
}

static int open8_save_context(struct target *target)
{
	unsigned int i;

	/* get pointers to arch-specific information */
	struct open8_common *open8 = target_to_open8(target);

	/* read core registers */
	open8_read_regs(target, open8->core_regs);

	for (i = 0; i < OPEN8_NUM_REGS; i++) {
		if (!open8->core_cache->reg_list[i].valid)
			open8->read_core_reg(target, i);
	}

	return ERROR_OK;
}
static int open8_restore_context(struct target *target)
{
	unsigned int i;

	/* get pointers to arch-specific information */
	struct open8_common *open8 = target_to_open8(target);

	for (i = 0; i < OPEN8_NUM_REGS; i++) {
		if (open8->core_cache->reg_list[i].dirty){
			open8->write_core_reg(target, i);
		}
	}

	/* write core regs */
	open8_write_regs(target, open8->core_regs);

	return ERROR_OK;
}

static int open8_debug_entry(struct target *target)
{
	struct open8_common *open8 = target_to_open8(target);


	open8_save_context(target);

	/* make sure stepping disabled STE bit in CSR1 cleared */
	/*stm8_config_step(target, 0);*/

	/* attempt to find halt reason */
	/*stm8_examine_debug_reason(target);*/

	LOG_DEBUG("entered debug state at PC 0x%" PRIx16 ", target->state: %s",
		buf_get_u32(open8->core_cache->reg_list[OPEN8_PC].value, 0, 32),
		target_state_name(target));

	return ERROR_OK;
}

static int open8_poll(struct target *target)
{

	int retval = ERROR_OK;
    struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;
    uint32_t dmstatus = open8_read_dmi(ejtag_info, 0x11);
	open8_bypass(ejtag_info);

	/* check for processor halted */
	if(dmstatus & 0x300){ 
	// 0x300 = 1100000000
	// only check if allhalted and anyhalted of dmstatus is set but the state of CPU is not halted.
		if (target->state != TARGET_HALTED) {
			if (target->state == TARGET_UNKNOWN)
				LOG_DEBUG("already set during server startup.");

			retval = open8_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_DEBUG("open8_debug_entry failed retval=%d", retval);
				return ERROR_TARGET_FAILURE;
			}

			if (target->state == TARGET_DEBUG_RUNNING) {
				target->state = TARGET_HALTED;
				target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
			} else {
				target->state = TARGET_HALTED;
				target_call_event_callbacks(target, TARGET_EVENT_HALTED);
			}
		}
    }else
		target->state = TARGET_RUNNING;
		LOG_DEBUG(" target->state: %s",	target_state_name(target));
	return ERROR_OK;

}


void halt(struct target *target){
	if(target->state != TARGET_HALTED){
		struct open8_common *open8 = target_to_open8(target);
		struct mips_ejtag *ejtag_info = &open8->ejtag_info;
		open8_write_dmi(ejtag_info, 0x10, 0x00000001);
		open8_write_dmi(ejtag_info, 0x10, 0x80000001);
		//open8_write_dmi(ejtag_info, 0x10, 0x80000001);
		open8_bypass(ejtag_info);
		//target->state = TARGET_HALTED;
	}
}

static int open8_halt(struct target *target)
{
	LOG_DEBUG("target->state: %s", target_state_name(target));
	halt(target);
	/*struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;
	uint32_t retval = open8_read_dmi(ejtag_info, 0x11);
	LOG_DEBUG("DMCONTROL 0x%8.8" PRIx32 "", retval);*/
	//open8_read_dmi(ejtag_info, 0x11, &retval);
    
	
	//uint32_t retval;
	//mips_ejtag_init(ejtag_info);

	/*mips_ejtag_set_instr(ejtag_info, 0x10);

	ejtag_info->ejtag_ctrl = 0;
	mips_ejtag_drscan_32(ejtag_info, &ejtag_info->ejtag_ctrl);

	mips_ejtag_get_idcode(ejtag_info);
	
	LOG_DEBUG("DMCONTROL 0x%8.8" PRIx32 "", ejtag_info->ejtag_ctrl);
	LOG_DEBUG("IDCODE 0x%8.8" PRIx32 "", ejtag_info->idcode);*/
	/*open8_write_dmi(ejtag_info, 0x10, 0x00000001);
	open8_write_dmi(ejtag_info, 0x10, 0x80000001);
	open8_write_dmi(ejtag_info, 0x10, 0x80000001);*/
	

	if (target->state == TARGET_HALTED) {
		LOG_DEBUG("target was already halted");
		return ERROR_OK;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("target was in unknown state when halt was requested");

	if (target->state == TARGET_RESET) {
		/* we came here in a reset_halt or reset_init sequence
		 * debug entry was already prepared in stm8_assert_reset()
		 */
		target->debug_reason = DBG_REASON_DBGRQ;

		return ERROR_OK;
	}


	/* break processor */
	//open8_debug_stall(target);

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}
static int open8_exit_debug(struct target *target)
{
	struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;
	open8_write_dmi(ejtag_info, 0x10, 0x40000001);
	open8_bypass(ejtag_info);
	return ERROR_OK;
}

static int open8_resume(struct target *target, int current,
		target_addr_t address, int handle_breakpoints,
		int debug_execution)
{
	struct open8_common *open8 = target_to_open8(target);
	/*struct breakpoint *breakpoint = NULL;*/
	uint32_t resume_pc;

	LOG_DEBUG("%d " TARGET_ADDR_FMT " %d %d", current, address,
			handle_breakpoints, debug_execution);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/*if (!debug_execution) {
		target_free_all_working_areas(target);
		stm8_enable_breakpoints(target);
		stm8_enable_watchpoints(target);
		struct stm8_comparator *comparator_list = stm8->hw_break_list;
		stm8_set_hwbreak(target, comparator_list);
	}*/

	/* current = 1: continue on current pc,
	   otherwise continue at <address> */
	if (!current) {
		buf_set_u32(open8->core_cache->reg_list[OPEN8_PC].value,
			0, 32, address);
		open8->core_cache->reg_list[OPEN8_PC].dirty = true;
		open8->core_cache->reg_list[OPEN8_PC].valid = true;
	}

	if (!current)
		resume_pc = address;
	else
		resume_pc = buf_get_u32(
			open8->core_cache->reg_list[OPEN8_PC].value,
			0, 32);

	open8_restore_context(target);

	/* the front-end may request us not to handle breakpoints */
	/*if (handle_breakpoints) {*/
		/* Single step past breakpoint at current address */
		/*breakpoint = breakpoint_find(target, resume_pc);
		if (breakpoint) {
			LOG_DEBUG("unset breakpoint at " TARGET_ADDR_FMT,
					breakpoint->address);
			stm8_unset_breakpoint(target, breakpoint);
			stm8_single_step_core(target);
			stm8_set_breakpoint(target, breakpoint);
		}
	}*/

	/* disable interrupts if we are debugging */
	/*if (debug_execution)
		stm8_enable_interrupts(target, 0);*/

	/* exit debug mode */
	open8_exit_debug(target);
	target->debug_reason = DBG_REASON_NOTHALTED;

	/* registers are now invalid */
	register_cache_invalidate(open8->core_cache);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("target resumed at 0x%" PRIx32 "", resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("target debug resumed at 0x%" PRIx32 "", resume_pc);
	}

	return ERROR_OK;
}

/*static int testee_reset_assert(struct target *target)
{
	target->state = TARGET_RESET;
	return ERROR_OK;
}*/
static int testee_reset_deassert(struct target *target)
{
	target->state = TARGET_RUNNING;
	return ERROR_OK;
}
static int open8_arch_state(struct target *target)
{
	struct open8_common *open8 = target_to_open8(target);

	LOG_USER("target halted due to %s, pc: 0x%4.4" PRIx16 "",
		debug_reason_name(target),
		buf_get_u32(open8->core_cache->reg_list[OPEN8_PC].value, 0, 32));

	return ERROR_OK;
}
static const char *open8_get_gdb_arch(struct target *target)
{
	return "open8";
}

static int open8_read_memory(struct target *target, target_addr_t address,
		uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;

	LOG_DEBUG("address: " TARGET_ADDR_FMT ", size: 0x%8.8" PRIx32 ", count: 0x%8.8" PRIx32 "",
			address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	/* since we don't know if buffer is aligned, we allocate new mem that is always aligned */
	void *t = NULL;

	if (size > 1) {
		t = malloc(count * size * sizeof(uint8_t));
		if (t == NULL) {
			LOG_ERROR("Out of memory");
			return ERROR_FAIL;
		}
	} else
		t = buffer;

	/* if noDMA off, use DMAACC mode for memory read */
	//int retval = ERROR_OK;
	/*if (ejtag_info->impcode & EJTAG_IMP_NODMA)
		retval = mips32_pracc_read_mem(ejtag_info, address, size, count, t);
	else
		retval = mips32_dmaacc_read_mem(ejtag_info, address, size, count, t);*/

	/* mips32_..._read_mem with size 4/2 returns uint32_t/uint16_t in host */
	/* endianness, but byte array should represent target endianness       */
	/*if (ERROR_OK == retval) {
		switch (size) {
		case 4:
			target_buffer_set_u32_array(target, buffer, count, t);
			break;
		case 2:
			target_buffer_set_u16_array(target, buffer, count, t);
			break;
		}
	}*/
	uint32_t R2 = open8_read_dmi(ejtag_info, 0x06);
	open8_bypass(ejtag_info);
	uint32_t temp = (address << 16) | (R2 & 0xFFFF);
	open8_write_dmi(ejtag_info, 0x06, temp);
	open8_bypass(ejtag_info);
	open8_write_dmi(ejtag_info, 0x17, 0x0);
	open8_bypass(ejtag_info);
	uint32_t mem = open8_read_dmi(ejtag_info, 0x07);
	open8_bypass(ejtag_info);
	uint8_t mem_2 = (mem >> 8) & 0xFF;
	//target_buffer_set_u8(target, buffer, mem_2);
	*buffer = mem_2;
	if (size > 1)
		free(t);

	return ERROR_OK;
}
static int open8_write_memory(struct target *target, target_addr_t address,
		uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;

	LOG_DEBUG("address: " TARGET_ADDR_FMT ", size: 0x%8.8" PRIx32 ", count: 0x%8.8" PRIx32 "",
			address, size, count);

    LOG_DEBUG("value pointed to by buffer %d", *buffer);
	LOG_DEBUG("address pointed to by buffer %p", buffer);
	LOG_DEBUG("address of buffer %p", &buffer);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/*if (size == 4 && count > 32) {
		int retval = mips_m4k_bulk_write_memory(target, address, count, buffer);
		if (retval == ERROR_OK)
			return ERROR_OK;
		LOG_WARNING("Falling back to non-bulk write");
	}*/

	/* sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	/** correct endianness if we have word or hword access */
	/*void *t = NULL;
	if (size > 1) {*/
		/* mips32_..._write_mem with size 4/2 requires uint32_t/uint16_t in host */
		/* endianness, but byte array represents target endianness               */
		/*t = malloc(count * size * sizeof(uint8_t));
		if (t == NULL) {
			LOG_ERROR("Out of memory");
			return ERROR_FAIL;
		}

		switch (size) {
		case 4:
			target_buffer_get_u32_array(target, buffer, count, (uint32_t *)t);
			break;
		case 2:
			target_buffer_get_u16_array(target, buffer, count, (uint16_t *)t);
			break;
		}
		buffer = t;
	}*/

	/* if noDMA off, use DMAACC mode for memory write */
	/*int retval;
	if (ejtag_info->impcode & EJTAG_IMP_NODMA)
		retval = mips32_pracc_write_mem(ejtag_info, address, size, count, buffer);
	else
		retval = mips32_dmaacc_write_mem(ejtag_info, address, size, count, buffer);

	free(t);

	if (ERROR_OK != retval)
		return retval;*/
	for(uint32_t i = 0; i < count * size; i++){
		LOG_DEBUG("%d : %x", (int)address + i, *buffer);
		uint32_t R2 = open8_read_dmi(ejtag_info, 0x06);
	    open8_bypass(ejtag_info);
		//int new_address = (int)address + i;
	    uint32_t temp = ((address+i) << 16) | (R2 & 0xFFFF);
		LOG_DEBUG("%d", temp);
	    open8_write_dmi(ejtag_info, 0x06, temp);
	    open8_bypass(ejtag_info);
	    uint32_t data_in = *buffer & 0xff;
        uint32_t R3 = open8_read_dmi(ejtag_info, 0x07);
	    open8_bypass(ejtag_info);
        uint32_t temp2 = data_in | (R3 & 0xffffff00) ;
        open8_write_dmi(ejtag_info, 0x07, temp2);
        open8_bypass(ejtag_info);
	    open8_write_dmi(ejtag_info, 0x20, 0x3);
        open8_bypass(ejtag_info);
	    open8_write_dmi(ejtag_info, 0x17, 0x0);
        open8_bypass(ejtag_info);
	    open8_write_dmi(ejtag_info, 0x20, 0x0);
        open8_bypass(ejtag_info);
		buffer++;
	}
	/*uint32_t R2 = open8_read_dmi(ejtag_info, 0x06);
	open8_bypass(ejtag_info);
	uint32_t temp = (address << 16) | (R2 & 0xFFFF);
	open8_write_dmi(ejtag_info, 0x06, temp);
	open8_bypass(ejtag_info);
	uint32_t data_in = *buffer & 0xff;
    uint32_t R3 = open8_read_dmi(ejtag_info, 0x07);
	open8_bypass(ejtag_info);
    uint32_t temp2 = data_in | (R3 & 0xffffff00) ;
    open8_write_dmi(ejtag_info, 0x07, temp2);
    open8_bypass(ejtag_info);
	open8_write_dmi(ejtag_info, 0x20, 0x3);
    open8_bypass(ejtag_info);
	open8_write_dmi(ejtag_info, 0x17, 0x0);
    open8_bypass(ejtag_info);
	open8_write_dmi(ejtag_info, 0x20, 0x0);
    open8_bypass(ejtag_info);*/
	return ERROR_OK;
}
static int open8_reset_assert(struct target *target)
{
	struct open8_common *open8 = target_to_open8(target);
	struct mips_ejtag *ejtag_info = &open8->ejtag_info;

	int res = ERROR_OK;
	//bool use_srst_fallback = true;

	enum reset_types jtag_reset_config = jtag_get_reset_config();

	bool srst_asserted = false;

	if (!(jtag_reset_config & RESET_SRST_PULLS_TRST) &&
			(jtag_reset_config & RESET_SRST_NO_GATING)) {
		jtag_add_reset(0, 1);
		srst_asserted = true;
	}

	if (!srst_asserted) {
		LOG_DEBUG("Hardware srst not supported, falling back to swim reset");
		//res = swim_system_reset();
		//if (res != ERROR_OK)
		//	return res;
		open8_write_dmi(ejtag_info, 0x10, 0x00000002);
		open8_bypass(ejtag_info);
		open8_write_dmi(ejtag_info, 0x10, 0x00000000);
		open8_bypass(ejtag_info);

	}

	/* registers are now invalid */
	register_cache_invalidate(open8->core_cache);

	target->state = TARGET_RESET;
	target->debug_reason = DBG_REASON_NOTHALTED;

	if (target->reset_halt) {
		res = target_halt(target);
		if (res != ERROR_OK)
			return res;
	}

	return ERROR_OK;
}

struct target_type testee_target = {
	.name = "testee",
	.commands = testee_command_handlers,
	.arch_state = open8_arch_state,

	.poll = &open8_poll,
	.halt = &open8_halt,
	.resume = open8_resume,
	.assert_reset = open8_reset_assert,
	.deassert_reset = &testee_reset_deassert,

	.read_memory = open8_read_memory,
	.write_memory = open8_write_memory,

	.get_gdb_reg_list = &open8_get_gdb_reg_list,
	.get_gdb_arch = &open8_get_gdb_arch,
	
	.target_create = &open8_target_create,
	.init_target = &open8_init,
	.examine = &open8_examine,
};