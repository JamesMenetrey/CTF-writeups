//
//      This file should be used in the following way:
//         - reload executable into IDA with using switch -c
//         - use File, Load IDC file and load this file.
//
//      NOTE: This file doesn't contain all information from the database.
//

#define UNLOADED_FILE   1
#include <idc.idc>

static main(void)
{
  // set 'loading idc file' mode
  set_inf_attr(INF_GENFLAGS, INFFL_LOADIDC|get_inf_attr(INF_GENFLAGS));
  GenInfo();            // various settings
  Segments();           // segmentation
  Enums();              // enumerations
  Structures();         // structure types
  ApplyStrucTInfos();   // structure type infos
  Patches();            // manual patches
  SegRegs();            // segment register values
  Bytes();              // individual bytes (code,data)
  Functions();          // function definitions
  // clear 'loading idc file' mode
  set_inf_attr(INF_GENFLAGS, ~INFFL_LOADIDC&get_inf_attr(INF_GENFLAGS));
}

//------------------------------------------------------------------------
// General information

static GenInfo(void) {

        delete_all_segments();    // purge database
	set_processor_type("metapc", SETPROC_USER);
	set_inf_attr(INF_COMPILER, 6);
	set_inf_attr(INF_STRLIT_BREAK, 0xA);
	set_flag(INF_CMTFLAG, SW_ALLCMT, 0);
	set_flag(INF_OUTFLAGS, OFLG_SHOW_VOID, 0);
	set_inf_attr(INF_XREFNUM, 2);
	set_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO, 1);
	set_inf_attr(INF_INDENT, 16);
	set_inf_attr(INF_COMMENT, 40);
	set_inf_attr(INF_MAXREF, 0x10);
	add_default_til("gnulnx_x86");
}

//------------------------------------------------------------------------
// Information about segmentation

static Segments(void) {
	set_selector(0X1,0);
	set_selector(0X2,0);
	set_selector(0X3,0);
	set_selector(0X4,0);
	set_selector(0X5,0);
	set_selector(0X6,0);
	set_selector(0X7,0);
	set_selector(0X8,0);
	set_selector(0X9,0);
	set_selector(0XA,0);
	;
	add_segm_ex(0X8048000,0X8048200,0X1,1,6,2,ADDSEG_NOSREG);
	SegRename(0X8048000,"LOAD");
	SegClass (0X8048000,"DATA");
	SegDefReg(0x8048000,"es",0x0);
	SegDefReg(0x8048000,"ss",0x0);
	SegDefReg(0x8048000,"ds",0x8);
	SegDefReg(0x8048000,"fs",0x0);
	SegDefReg(0x8048000,"gs",0x0);
	set_segm_type(0X8048000,3);
	add_segm_ex(0X8049000,0X8049030,0X5,1,3,2,ADDSEG_NOSREG);
	SegRename(0X8049000,".plt");
	SegClass (0X8049000,"CODE");
	SegDefReg(0x8049000,"ds",0x8);
	set_segm_type(0X8049000,2);
	add_segm_ex(0X8049030,0X80491EA,0X6,1,3,2,ADDSEG_NOSREG);
	SegRename(0X8049030,".text");
	SegClass (0X8049030,"CODE");
	SegDefReg(0x8049030,"ds",0x8);
	set_segm_type(0X8049030,2);
	add_segm_ex(0X804AF58,0X804B000,0X4,1,6,2,ADDSEG_NOSREG);
	SegRename(0X804AF58,"LOAD");
	SegClass (0X804AF58,"DATA");
	SegDefReg(0x804AF58,"es",0x0);
	SegDefReg(0x804AF58,"ss",0x0);
	SegDefReg(0x804AF58,"ds",0x8);
	SegDefReg(0x804AF58,"fs",0x0);
	SegDefReg(0x804AF58,"gs",0x0);
	set_segm_type(0X804AF58,3);
	add_segm_ex(0X804B000,0X804B014,0X7,1,5,2,ADDSEG_NOSREG);
	SegRename(0X804B000,".got.plt");
	SegClass (0X804B000,"DATA");
	SegDefReg(0x804B000,"ds",0x8);
	set_segm_type(0X804B000,3);
	add_segm_ex(0X804B014,0X804B146,0X8,1,5,2,ADDSEG_NOSREG);
	SegRename(0X804B014,".data");
	SegClass (0X804B014,"DATA");
	SegDefReg(0x804B014,"ds",0x8);
	set_segm_type(0X804B014,3);
	add_segm_ex(0X804B148,0X804B149,0X9,1,1,2,ADDSEG_NOSREG|ADDSEG_SPARSE);
	SegRename(0X804B148,".prgend");
	SegClass (0X804B148,".prgend");
	set_segm_type(0X804B148,7);
	add_segm_ex(0X804B14C,0X804B154,0XA,1,5,2,ADDSEG_NOSREG|ADDSEG_SPARSE);
	SegRename(0X804B14C,"extern");
	SegClass (0X804B14C,"extern");
	set_segm_type(0X804B14C,1);
	set_inf_attr(INF_LOW_OFF, 0x8048000);
	set_inf_attr(INF_HIGH_OFF, 0xBFF9B000);
}

//------------------------------------------------------------------------
// Information about enum types

static Enums(void) {
        auto id;
        begin_type_updating(UTP_ENUM);
        end_type_updating(UTP_ENUM);
}

static ApplyStrucTInfos_0(void) {
        auto id;
	id = get_struc_id("Elf32_Sym");
	SetType(get_member_id(id, 0x0), "unsigned __int32");
	SetType(get_member_id(id, 0x4), "unsigned __int32");
	SetType(get_member_id(id, 0x8), "unsigned __int32");
	SetType(get_member_id(id, 0xC), "unsigned __int8");
	SetType(get_member_id(id, 0xD), "unsigned __int8");
	SetType(get_member_id(id, 0xE), "unsigned __int16");
	id = get_struc_id("Elf32_Rel");
	SetType(get_member_id(id, 0x0), "unsigned __int32");
	SetType(get_member_id(id, 0x4), "unsigned __int32");
	id = get_struc_id("Elf32_Dyn");
	SetType(get_member_id(id, 0x0), "__int32");
	SetType(get_member_id(id, 0x4), "union Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249");
	id = get_struc_id("Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249");
	SetType(get_member_id(id, 0x0), "unsigned __int32");
	SetType(get_member_id(id, 0x1), "unsigned __int32");
	return id;
}

//------------------------------------------------------------------------
// Information about type information for structure members

static ApplyStrucTInfos() {
	ApplyStrucTInfos_0();
}

static Structures_0(id) {
        auto mid;

	id = add_struc(-1,"Elf32_Sym",0);
	id = add_struc(-1,"Elf32_Rel",0);
	id = add_struc(-1,"Elf32_Dyn",0);
	id = add_struc(-1,"Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249",1);
	
	id = get_struc_id("Elf32_Sym");
	mid = add_struc_member(id,"st_name",	0,	0x20500400,	0X80481A8,	4,	0XFFFFFFFF,	0,	0x000002);
	mid = add_struc_member(id,"st_value",	0X4,	0x20500400,	0,	4,	0XFFFFFFFF,	0,	0x000002);
	mid = add_struc_member(id,"st_size",	0X8,	0x20000400,	-1,	4);
	mid = add_struc_member(id,"st_info",	0XC,	0x000400,	-1,	1);
	mid = add_struc_member(id,"st_other",	0XD,	0x000400,	-1,	1);
	mid = add_struc_member(id,"st_shndx",	0XE,	0x10000400,	-1,	2);
	set_struc_align(id,2);
	
	id = get_struc_id("Elf32_Rel");
	mid = add_struc_member(id,"r_offset",	0,	0x20000400,	-1,	4);
	mid = add_struc_member(id,"r_info",	0X4,	0x20000400,	-1,	4);
	set_struc_align(id,2);
	
	id = get_struc_id("Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249");
	mid = add_struc_member(id,"d_val",	0,	0x20000400,	-1,	4);
	mid = add_struc_member(id,"d_ptr",	0,	0x20000400,	-1,	4);
	set_struc_align(id,2);
	
	id = get_struc_id("Elf32_Dyn");
	mid = add_struc_member(id,"d_tag",	0,	0x20000400,	-1,	4);
	mid = add_struc_member(id,"d_un",	0X4,	0x60000400,	get_struc_id("Elf32_Dyn::$A263394DDF3EC2D4B1B8448EDD30E249"),	4);
	set_struc_align(id,2);
	return id;
}

//------------------------------------------------------------------------
// Information about structure types

static Structures(void) {
        auto id;
        begin_type_updating(UTP_STRUCT);
	id = Structures_0(id);
}

//------------------------------------------------------------------------
// Information about bytes

static Bytes_0(void) {
        auto x;
#define id x

	set_cmt	(0X8048000,	"File format: \\x7FELF",	0);
	update_extra_cmt		(0X8048000,	E_PREV + 0,	"; File Name   : C:\\Users\\root\\Desktop\\foo");
	update_extra_cmt		(0X8048000,	E_PREV + 1,	"; Format      : ELF for Intel 386 (Executable)");
	update_extra_cmt		(0X8048000,	E_PREV + 2,	"; Imagebase   : 8048000");
	update_extra_cmt		(0X8048000,	E_PREV + 3,	"; Interpreter '/lib/ld-linux.so.2'");
	update_extra_cmt		(0X8048000,	E_PREV + 4,	"; Needed Library 'libc.so.6'");
	update_extra_cmt		(0X8048000,	E_PREV + 5,	"; ");
	update_extra_cmt		(0X8048000,	E_PREV + 6,	"; Source File : 'foo.asm'");
	create_dword	(x=0X8048000);
	op_hex		(x,	0);
	set_cmt	(0X8048004,	"File class: 32-bit",	0);
	create_byte	(x=0X8048004);
	op_hex		(x,	0);
	set_cmt	(0X8048005,	"Data encoding: little-endian",	0);
	create_byte	(x=0X8048005);
	op_hex		(x,	0);
	set_cmt	(0X8048006,	"File version",	0);
	create_byte	(x=0X8048006);
	op_hex		(x,	0);
	set_cmt	(0X8048007,	"OS/ABI: UNIX System V ABI",	0);
	create_byte	(x=0X8048007);
	op_hex		(x,	0);
	set_cmt	(0X8048008,	"ABI Version",	0);
	create_byte	(x=0X8048008);
	op_hex		(x,	0);
	set_cmt	(0X8048009,	"Padding",	0);
	create_byte	(x=0X8048009);
	make_array	(x,	0X7);
	op_hex		(x,	0);
	set_cmt	(0X8048010,	"File type: Executable",	0);
	create_word	(x=0X8048010);
	op_hex		(x,	0);
	set_cmt	(0X8048012,	"Machine: Intel 386",	0);
	create_word	(x=0X8048012);
	op_hex		(x,	0);
	set_cmt	(0X8048014,	"File version",	0);
	create_dword	(x=0X8048014);
	op_hex		(x,	0);
	set_cmt	(0X8048018,	"Entry point",	0);
	create_dword	(x=0X8048018);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X804801C,	"PHT file offset",	0);
	create_dword	(x=0X804801C);
	op_hex		(x,	0);
	set_cmt	(0X8048020,	"SHT file offset",	0);
	create_dword	(x=0X8048020);
	op_hex		(x,	0);
	set_cmt	(0X8048024,	"Processor-specific flags",	0);
	create_dword	(x=0X8048024);
	op_hex		(x,	0);
	set_cmt	(0X8048028,	"ELF header size",	0);
	create_word	(x=0X8048028);
	op_hex		(x,	0);
	set_cmt	(0X804802A,	"PHT entry size",	0);
	create_word	(x=0X804802A);
	op_hex		(x,	0);
	set_cmt	(0X804802C,	"Number of entries in PHT",	0);
	create_word	(x=0X804802C);
	op_hex		(x,	0);
	set_cmt	(0X804802E,	"SHT entry size",	0);
	create_word	(x=0X804802E);
	op_hex		(x,	0);
	set_cmt	(0X8048030,	"Number of entries in SHT",	0);
	create_word	(x=0X8048030);
	op_hex		(x,	0);
	set_cmt	(0X8048032,	"SHT entry index for string table",	0);
	create_word	(x=0X8048032);
	op_hex		(x,	0);
	set_cmt	(0X8048034,	"Type: PHDR",	0);
	update_extra_cmt		(0X8048034,	E_PREV + 0,	"; ELF32 Program Header");
	update_extra_cmt		(0X8048034,	E_PREV + 1,	"; PHT Entry 0");
	create_dword	(x=0X8048034);
	op_hex		(x,	0);
	set_cmt	(0X8048038,	"File offset",	0);
	create_dword	(x=0X8048038);
	op_hex		(x,	0);
	set_cmt	(0X804803C,	"Virtual address",	0);
	create_dword	(x=0X804803C);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X8048040,	"Physical address",	0);
	create_dword	(x=0X8048040);
	op_hex		(x,	0);
	set_cmt	(0X8048044,	"Size in file image",	0);
	create_dword	(x=0X8048044);
	op_hex		(x,	0);
	set_cmt	(0X8048048,	"Size in memory image",	0);
	create_dword	(x=0X8048048);
	op_hex		(x,	0);
	set_cmt	(0X804804C,	"Flags",	0);
	create_dword	(x=0X804804C);
	op_hex		(x,	0);
	set_cmt	(0X8048050,	"Alignment",	0);
	create_dword	(x=0X8048050);
	op_hex		(x,	0);
	set_cmt	(0X8048054,	"Type: INTERP",	0);
	update_extra_cmt		(0X8048054,	E_PREV + 0,	"; PHT Entry 1");
	create_dword	(x=0X8048054);
	op_hex		(x,	0);
	set_cmt	(0X8048058,	"File offset",	0);
	create_dword	(x=0X8048058);
	op_hex		(x,	0);
	set_cmt	(0X804805C,	"Virtual address",	0);
	create_dword	(x=0X804805C);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X8048060,	"Physical address",	0);
	create_dword	(x=0X8048060);
	op_hex		(x,	0);
	set_cmt	(0X8048064,	"Size in file image",	0);
	create_dword	(x=0X8048064);
	op_hex		(x,	0);
	set_cmt	(0X8048068,	"Size in memory image",	0);
	create_dword	(x=0X8048068);
	op_hex		(x,	0);
	set_cmt	(0X804806C,	"Flags",	0);
	create_dword	(x=0X804806C);
	op_hex		(x,	0);
	set_cmt	(0X8048070,	"Alignment",	0);
	create_dword	(x=0X8048070);
	op_hex		(x,	0);
	set_cmt	(0X8048074,	"Type: LOAD",	0);
	update_extra_cmt		(0X8048074,	E_PREV + 0,	"; PHT Entry 2");
	create_dword	(x=0X8048074);
	op_hex		(x,	0);
	set_cmt	(0X8048078,	"File offset",	0);
	create_dword	(x=0X8048078);
	op_hex		(x,	0);
	set_cmt	(0X804807C,	"Virtual address",	0);
	create_dword	(x=0X804807C);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X8048080,	"Physical address",	0);
	create_dword	(x=0X8048080);
	op_hex		(x,	0);
	set_cmt	(0X8048084,	"Size in file image",	0);
	create_dword	(x=0X8048084);
	op_hex		(x,	0);
	set_cmt	(0X8048088,	"Size in memory image",	0);
	create_dword	(x=0X8048088);
	op_hex		(x,	0);
	set_cmt	(0X804808C,	"Flags",	0);
	create_dword	(x=0X804808C);
	op_hex		(x,	0);
	set_cmt	(0X8048090,	"Alignment",	0);
	create_dword	(x=0X8048090);
	op_hex		(x,	0);
	set_cmt	(0X8048094,	"Type: LOAD",	0);
	update_extra_cmt		(0X8048094,	E_PREV + 0,	"; PHT Entry 3");
	create_dword	(x=0X8048094);
	op_hex		(x,	0);
	set_cmt	(0X8048098,	"File offset",	0);
	create_dword	(x=0X8048098);
	op_hex		(x,	0);
	set_cmt	(0X804809C,	"Virtual address",	0);
	create_dword	(x=0X804809C);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X80480A0,	"Physical address",	0);
	create_dword	(x=0X80480A0);
	op_hex		(x,	0);
	set_cmt	(0X80480A4,	"Size in file image",	0);
	create_dword	(x=0X80480A4);
	op_hex		(x,	0);
	set_cmt	(0X80480A8,	"Size in memory image",	0);
	create_dword	(x=0X80480A8);
	op_hex		(x,	0);
	set_cmt	(0X80480AC,	"Flags",	0);
	create_dword	(x=0X80480AC);
	op_hex		(x,	0);
	set_cmt	(0X80480B0,	"Alignment",	0);
	create_dword	(x=0X80480B0);
	op_hex		(x,	0);
	set_cmt	(0X80480B4,	"Type: LOAD",	0);
	update_extra_cmt		(0X80480B4,	E_PREV + 0,	"; PHT Entry 4");
	create_dword	(x=0X80480B4);
	op_hex		(x,	0);
	set_cmt	(0X80480B8,	"File offset",	0);
	create_dword	(x=0X80480B8);
	op_hex		(x,	0);
	set_cmt	(0X80480BC,	"Virtual address",	0);
	create_dword	(x=0X80480BC);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X80480C0,	"Physical address",	0);
	create_dword	(x=0X80480C0);
	op_hex		(x,	0);
	set_cmt	(0X80480C4,	"Size in file image",	0);
	create_dword	(x=0X80480C4);
	op_hex		(x,	0);
	set_cmt	(0X80480C8,	"Size in memory image",	0);
	create_dword	(x=0X80480C8);
	op_hex		(x,	0);
	set_cmt	(0X80480CC,	"Flags",	0);
	create_dword	(x=0X80480CC);
	op_hex		(x,	0);
	set_cmt	(0X80480D0,	"Alignment",	0);
	create_dword	(x=0X80480D0);
	op_hex		(x,	0);
	set_cmt	(0X80480D4,	"Type: LOAD",	0);
	update_extra_cmt		(0X80480D4,	E_PREV + 0,	"; PHT Entry 5");
	create_dword	(x=0X80480D4);
	op_hex		(x,	0);
	set_cmt	(0X80480D8,	"File offset",	0);
	create_dword	(x=0X80480D8);
	op_hex		(x,	0);
	set_cmt	(0X80480DC,	"Virtual address",	0);
	create_dword	(x=0X80480DC);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X80480E0,	"Physical address",	0);
	create_dword	(x=0X80480E0);
	op_hex		(x,	0);
	set_cmt	(0X80480E4,	"Size in file image",	0);
	create_dword	(x=0X80480E4);
	op_hex		(x,	0);
	set_cmt	(0X80480E8,	"Size in memory image",	0);
	create_dword	(x=0X80480E8);
	op_hex		(x,	0);
	set_cmt	(0X80480EC,	"Flags",	0);
	create_dword	(x=0X80480EC);
	op_hex		(x,	0);
	set_cmt	(0X80480F0,	"Alignment",	0);
	create_dword	(x=0X80480F0);
	op_hex		(x,	0);
	set_cmt	(0X80480F4,	"Type: DYNAMIC",	0);
	update_extra_cmt		(0X80480F4,	E_PREV + 0,	"; PHT Entry 6");
	create_dword	(x=0X80480F4);
	op_hex		(x,	0);
	set_cmt	(0X80480F8,	"File offset",	0);
	create_dword	(x=0X80480F8);
	op_hex		(x,	0);
	set_cmt	(0X80480FC,	"Virtual address",	0);
	create_dword	(x=0X80480FC);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X8048100,	"Physical address",	0);
	create_dword	(x=0X8048100);
	op_hex		(x,	0);
	set_cmt	(0X8048104,	"Size in file image",	0);
	create_dword	(x=0X8048104);
	op_hex		(x,	0);
	set_cmt	(0X8048108,	"Size in memory image",	0);
	create_dword	(x=0X8048108);
	op_hex		(x,	0);
	set_cmt	(0X804810C,	"Flags",	0);
	create_dword	(x=0X804810C);
	op_hex		(x,	0);
	set_cmt	(0X8048110,	"Alignment",	0);
	create_dword	(x=0X8048110);
	op_hex		(x,	0);
	set_cmt	(0X8048114,	"Type: RO-AFTER",	0);
	update_extra_cmt		(0X8048114,	E_PREV + 0,	"; PHT Entry 7");
	create_dword	(x=0X8048114);
	op_hex		(x,	0);
	set_cmt	(0X8048118,	"File offset",	0);
	create_dword	(x=0X8048118);
	op_hex		(x,	0);
	set_cmt	(0X804811C,	"Virtual address",	0);
	create_dword	(x=0X804811C);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_cmt	(0X8048120,	"Physical address",	0);
	create_dword	(x=0X8048120);
	op_hex		(x,	0);
	set_cmt	(0X8048124,	"Size in file image",	0);
	create_dword	(x=0X8048124);
	op_hex		(x,	0);
	set_cmt	(0X8048128,	"Size in memory image",	0);
	create_dword	(x=0X8048128);
	op_hex		(x,	0);
	set_cmt	(0X804812C,	"Flags",	0);
	create_dword	(x=0X804812C);
	op_hex		(x,	0);
	set_cmt	(0X8048130,	"Alignment",	0);
	create_dword	(x=0X8048130);
	op_hex		(x,	0);
	create_strlit	(0X8048134,	0X8048147);
	set_name	(0X8048134,	"aLibLdLinuxSo2");
	update_extra_cmt		(0X8048148,	E_PREV + 0,	"; ELF Hash Table");
	create_dword	(x=0X8048148);
	op_hex		(x,	0);
	set_name	(0X8048148,	"elf_hash_nbucket");
	create_dword	(x=0X804814C);
	op_hex		(x,	0);
	set_name	(0X804814C,	"elf_hash_nchain");
	create_dword	(x=0X8048150);
	op_hex		(x,	0);
	set_name	(0X8048150,	"elf_hash_bucket");
	create_dword	(x=0X8048154);
	make_array	(x,	0X3);
	op_hex		(x,	0);
	set_name	(0X8048154,	"elf_hash_chain");
	update_extra_cmt		(0X8048160,	E_PREV + 0,	"; ELF GNU Hash Table");
	create_dword	(x=0X8048160);
	op_hex		(x,	0);
	set_name	(0X8048160,	"elf_gnu_hash_nbuckets");
	create_dword	(x=0X8048164);
	op_hex		(x,	0);
	set_name	(0X8048164,	"elf_gnu_hash_symbias");
	create_dword	(x=0X8048168);
	op_hex		(x,	0);
	set_name	(0X8048168,	"elf_gnu_hash_bitmask_nwords");
	create_dword	(x=0X804816C);
	op_hex		(x,	0);
	set_name	(0X804816C,	"elf_gnu_hash_shift");
	create_dword	(x=0X8048170);
	op_hex		(x,	0);
	set_name	(0X8048170,	"elf_gnu_hash_indexes");
	create_dword	(x=0X8048174);
	op_hex		(x,	0);
	set_name	(0X8048174,	"elf_gnu_hash_bucket");
	update_extra_cmt		(0X8048178,	E_PREV + 0,	"; ELF Symbol Table");
	MakeStruct	(0X8048178,	"Elf32_Sym");
	MakeStruct	(0X8048188,	"Elf32_Sym");
	MakeStruct	(0X8048198,	"Elf32_Sym");
	update_extra_cmt		(0X80481A8,	E_PREV + 0,	"; ELF String Table");
	create_strlit	(0X80481A9,	0X80481B3);
	set_name	(0X80481A9,	"aLibcSo6");
	create_strlit	(0X80481B3,	0X80481B8);
	set_name	(0X80481B3,	"aPuts");
	create_strlit	(0X80481B8,	0X80481BF);
	set_name	(0X80481B8,	"aStrlen");
	create_strlit	(0X80481BF,	0X80481C9);
	set_name	(0X80481BF,	"aGlibc20");
	make_array	(0X80481C9,	0X3);
	set_cmt	(0X80481F0,	"R_386_JMP_SLOT puts",	0);
	update_extra_cmt		(0X80481F0,	E_PREV + 0,	"; ELF JMPREL Relocation Table");
	MakeStruct	(0X80481F0,	"Elf32_Rel");
	set_cmt	(0X80481F8,	"R_386_JMP_SLOT strlen",	0);
	MakeStruct	(0X80481F8,	"Elf32_Rel");
	create_insn	(0X8049000);
	make_array	(0X804900C,	0X4);
	create_insn	(0X8049010);
	set_name	(0X8049010,	".puts");
	create_insn	(0X8049016);
	create_insn	(0X8049020);
	set_name	(0X8049020,	".strlen");
	create_insn	(0X8049026);
	create_insn	(0X8049030);
	set_name	(0X8049030,	"main");
	set_cmt	(0X8049033,	"Check for missing key (args != 2)",	0);
	create_insn	(x=0X8049033);
	op_stkvar	(x,	0);
	create_insn	(x=0X8049039);
	op_stkvar	(x,	1);
	set_cmt	(0X8049040,	"param_ptr_key",	0);
	create_insn	(x=0X804904B);
	op_plain_offset	(x,	1,	0);
	op_plain_offset	(x,	129,	0);
	set_name	(0X804904B,	"missing_key");
	set_cmt	(0X8049051,	"s",	0);
	create_insn	(0X804905C);
	set_name	(0X804905C,	"check_key");
	create_insn	(x=0X804905F);
	op_stkvar	(x,	1);
	set_cmt	(0X8049069,	"s",	0);
	create_insn	(x=0X804906F);
	op_dec		(x,	1);
	update_extra_cmt		(0X8049072,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049072,	E_PREV + 1,	"; Must be = 16 chars");
	update_extra_cmt		(0X8049072,	E_PREV + 2,	";");
	update_extra_cmt		(0X8049084,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049084,	E_PREV + 1,	"; [0] uppercase = [2] lowercase (-32)");
	update_extra_cmt		(0X8049084,	E_PREV + 2,	";");
	update_extra_cmt		(0X8049094,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049094,	E_PREV + 1,	"; [1] = [6]");
	update_extra_cmt		(0X8049094,	E_PREV + 2,	";");
	update_extra_cmt		(0X804909F,	E_PREV + 0,	";");
	update_extra_cmt		(0X804909F,	E_PREV + 1,	"; [1] = 0");
	update_extra_cmt		(0X804909F,	E_PREV + 2,	";");
	update_extra_cmt		(0X80490AF,	E_PREV + 0,	";");
	update_extra_cmt		(0X80490AF,	E_PREV + 1,	"; [8] = 1");
	update_extra_cmt		(0X80490AF,	E_PREV + 2,	";");
	create_insn	(x=0X80490B5);
	op_dec		(x,	1);
	update_extra_cmt		(0X80490C0,	E_PREV + 0,	";");
	update_extra_cmt		(0X80490C0,	E_PREV + 1,	"; [12] = 3");
	update_extra_cmt		(0X80490C0,	E_PREV + 2,	";");
	update_extra_cmt		(0X80490D5,	E_PREV + 0,	";");
	update_extra_cmt		(0X80490D5,	E_PREV + 1,	"; [4] uppercase = [7] lowercase");
	update_extra_cmt		(0X80490D5,	E_PREV + 2,	";");
	create_insn	(x=0X80490DF);
	op_dec		(x,	1);
	update_extra_cmt		(0X80490E6,	E_PREV + 0,	";");
	update_extra_cmt		(0X80490E6,	E_PREV + 1,	"; [10] = [9]-1");
	update_extra_cmt		(0X80490E6,	E_PREV + 2,	";");
	create_insn	(x=0X80490F0);
	op_chr		(x,	1);
	update_extra_cmt		(0X80490F3,	E_PREV + 0,	";");
	update_extra_cmt		(0X80490F3,	E_PREV + 1,	"; [3] = '_'");
	update_extra_cmt		(0X80490F3,	E_PREV + 2,	";");
	create_insn	(x=0X80490FD);
	op_dec		(x,	1);
	update_extra_cmt		(0X8049105,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049105,	E_PREV + 1,	"; [10] = [4]+2");
	update_extra_cmt		(0X8049105,	E_PREV + 2,	";");
	create_insn	(x=0X8049107);
	op_dec		(x,	1);
	create_insn	(x=0X8049110);
	op_hex		(x,	1);
	update_extra_cmt		(0X8049116,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049116,	E_PREV + 1,	"; [14] = !");
	update_extra_cmt		(0X8049116,	E_PREV + 2,	";");
	update_extra_cmt		(0X8049127,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049127,	E_PREV + 1,	"; [2] = w");
	update_extra_cmt		(0X8049127,	E_PREV + 2,	";");
	update_extra_cmt		(0X8049138,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049138,	E_PREV + 1,	"; [4] = f");
	update_extra_cmt		(0X8049138,	E_PREV + 2,	";");
	create_insn	(x=0X804913E);
	op_dec		(x,	1);
	update_extra_cmt		(0X8049149,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049149,	E_PREV + 1,	"; [5] ^ [11] = 0x1b");
	update_extra_cmt		(0X8049149,	E_PREV + 2,	";");
	set_cmt	(0X804914B,	"eax = [5]",	0);
	set_cmt	(0X804914D,	"ebx = [11]",	0);
	set_cmt	(0X804914F,	"ecx = [5] + [11]",	0);
	update_extra_cmt		(0X8049155,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049155,	E_PREV + 1,	"; [5] + [11] = 0xA3");
	update_extra_cmt		(0X8049155,	E_PREV + 2,	";");
	set_cmt	(0X8049157,	"ebx = [11] - [5]",	0);
	set_cmt	(0X8049159,	"[11] - [5] = 5",	0);
	update_extra_cmt		(0X804915C,	E_PREV + 0,	";");
	update_extra_cmt		(0X804915C,	E_PREV + 1,	"; [11] - [5] = 5");
	update_extra_cmt		(0X804915C,	E_PREV + 2,	";");
	create_insn	(x=0X804915E);
	op_dec		(x,	1);
	create_insn	(x=0X8049162);
	op_chr		(x,	1);
	update_extra_cmt		(0X8049165,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049165,	E_PREV + 1,	"; [13] = r");
	update_extra_cmt		(0X8049165,	E_PREV + 2,	";");
	create_insn	(x=0X8049167);
	op_dec		(x,	1);
	create_insn	(x=0X804916B);
	op_dec		(x,	1);
	update_extra_cmt		(0X8049171,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049171,	E_PREV + 1,	"; [15] = [14]");
	update_extra_cmt		(0X8049171,	E_PREV + 2,	";");
	create_insn	(x=0X804917A);
	op_plain_offset	(x,	1,	0);
	op_plain_offset	(x,	129,	0);
	set_name	(0X804917A,	"wrong_key");
	set_cmt	(0X8049180,	"s",	0);
	create_insn	(0X804918B);
	set_name	(0X804918B,	"good_key");
	create_insn	(x=0X8049192);
	op_plain_offset	(x,	1,	0);
	op_plain_offset	(x,	129,	0);
	update_extra_cmt		(0X8049198,	E_PREV + 0,	";");
	update_extra_cmt		(0X8049198,	E_PREV + 1,	"; ebx = 0");
	update_extra_cmt		(0X8049198,	E_PREV + 2,	"; ecx = 0");
	update_extra_cmt		(0X8049198,	E_PREV + 3,	"; esi = ptr enc_flag");
	update_extra_cmt		(0X8049198,	E_PREV + 4,	";");
	set_name	(0X8049198,	"decrypt_flag_loop");
	set_cmt	(0X80491B2,	"s",	0);
	create_insn	(0X80491BA);
	set_name	(0X80491BA,	"shake");
	create_insn	(x=0X80491BF);
	op_stkvar	(x,	1);
	create_insn	(x=0X80491C2);
	op_stkvar	(x,	1);
	create_insn	(x=0X80491C7);
	op_hex		(x,	1);
	create_insn	(x=0X80491CD);
	op_hex		(x,	1);
	create_insn	(x=0X80491D0);
	op_hex		(x,	1);
	set_name	(0X80491DC,	"f0o.foO");
	create_insn	(0X80491DE);
	set_name	(0X80491DE,	"exit");
	set_cmt	(0X80491E3,	"status",	0);
	set_cmt	(0X80491E8,	"LINUX - sys_exit",	0);
	create_insn	(x=0X80491E8);
	op_hex		(x,	0);
	set_cmt	(0X804AF58,	"DT_NEEDED libc.so.6",	0);
	update_extra_cmt		(0X804AF58,	E_PREV + 0,	"; ELF Dynamic Information");
	MakeStruct	(0X804AF58,	"Elf32_Dyn");
	set_name	(0X804AF58,	"_DYNAMIC");
	set_cmt	(0X804AF60,	"DT_HASH ",	0);
	MakeStruct	(0X804AF60,	"Elf32_Dyn");
	set_cmt	(0X804AF68,	"DT_GNU_HASH ",	0);
	MakeStruct	(0X804AF68,	"Elf32_Dyn");
	set_cmt	(0X804AF70,	"DT_STRTAB ",	0);
	MakeStruct	(0X804AF70,	"Elf32_Dyn");
	set_cmt	(0X804AF78,	"DT_SYMTAB ",	0);
	MakeStruct	(0X804AF78,	"Elf32_Dyn");
	set_cmt	(0X804AF80,	"DT_STRSZ ",	0);
	MakeStruct	(0X804AF80,	"Elf32_Dyn");
	set_cmt	(0X804AF88,	"DT_SYMENT ",	0);
	MakeStruct	(0X804AF88,	"Elf32_Dyn");
	set_cmt	(0X804AF90,	"DT_DEBUG ",	0);
	MakeStruct	(0X804AF90,	"Elf32_Dyn");
	set_cmt	(0X804AF98,	"DT_PLTGOT ",	0);
	MakeStruct	(0X804AF98,	"Elf32_Dyn");
	set_cmt	(0X804AFA0,	"DT_PLTRELSZ ",	0);
	MakeStruct	(0X804AFA0,	"Elf32_Dyn");
	set_cmt	(0X804AFA8,	"DT_PLTREL ",	0);
	MakeStruct	(0X804AFA8,	"Elf32_Dyn");
	set_cmt	(0X804AFB0,	"DT_JMPREL ",	0);
	MakeStruct	(0X804AFB0,	"Elf32_Dyn");
	set_cmt	(0X804AFB8,	"DT_VERNEED ",	0);
	MakeStruct	(0X804AFB8,	"Elf32_Dyn");
	set_cmt	(0X804AFC0,	"DT_VERNEEDNUM ",	0);
	MakeStruct	(0X804AFC0,	"Elf32_Dyn");
	set_cmt	(0X804AFC8,	"DT_VERSYM ",	0);
	MakeStruct	(0X804AFC8,	"Elf32_Dyn");
	set_cmt	(0X804AFD0,	"DT_NULL ",	0);
	MakeStruct	(0X804AFD0,	"Elf32_Dyn");
	make_array	(0X804AFD8,	0X28);
	create_dword	(x=0X804B000);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_name	(0X804B000,	"_GLOBAL_OFFSET_TABLE_");
	create_dword	(0X804B004);
	create_dword	(0X804B008);
	create_dword	(x=0X804B00C);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_name	(0X804B00C,	"puts_ptr");
	create_dword	(x=0X804B010);
	op_plain_offset	(x,	0,	0);
	op_plain_offset	(x,	128,	0);
	set_name	(0X804B010,	"strlen_ptr");
	create_strlit	(0X804B014,	0X804B03F);
	set_name	(0X804B014,	"str_no_key");
	create_strlit	(0X804B03F,	0X804B05A);
	set_name	(0X804B03F,	"Foo");
	create_strlit	(0X804B05A,	0X804B070);
	set_name	(0X804B05A,	"str_wrong_key");
	create_byte	(0X804B070);
	set_name	(0X804B070,	"str_encrypted_flag");
	set_name	(0X804B148,	"_end");
	create_insn	(0X804B14C);
	set_name	(0X804B14C,	"puts");
	create_insn	(0X804B150);
	set_name	(0X804B150,	"strlen");
}

static Functions_0(void) {

	add_func    (0X8049000,0X804900C);
	set_func_flags(0X8049000,0x400);
	add_func    (0X8049010,0X8049016);
	set_func_flags(0X8049010,0x44c0);
	SetType(0X8049010, "int puts(const char *s);");
	set_frame_size(0X8049010, 0, 0, 0);
	define_local_var(0X8049010, 0X8049016, "[bp+0X4]", "s");
	add_func    (0X8049020,0X8049026);
	set_func_flags(0X8049020,0x44c0);
	SetType(0X8049020, "size_t strlen(const char *s);");
	set_frame_size(0X8049020, 0, 0, 0);
	define_local_var(0X8049020, 0X8049026, "[bp+0X4]", "s");
	add_func    (0X8049030,0X804905C);
	set_func_flags(0X8049030,0x4411);
	SetType(0X8049030, "void __cdecl __noreturn main(int, char *s);");
	set_frame_size(0X8049030, 0, 4, 0);
	define_local_var(0X8049030, 0X804905C, "[bp+0XC]", "s");
	add_func    (0X804905C,0X804918B);
	set_func_flags(0X804905C,0x4410);
	SetType(0X804905C, "int __cdecl check_key(char *param_ptr_key);");
	set_frame_size(0X804905C, 0, 4, 0);
	define_local_var(0X804905C, 0X804918B, "[bp+0X8]", "param_ptr_key");
	define_local_var(0X804905C, 0X804918B, "edi", "ref_ptr_key");
	add_func    (0X804918B,0X80491BA);
	set_func_flags(0X804918B,0x4410);
	SetType(0X804918B, "int __usercall good_key@<eax>(int key@<edi>);");
	set_frame_size(0X804918B, 0, 4, 0);
	define_local_var(0X804918B, 0X80491BA, "ebx", "index");
	define_local_var(0X804918B, 0X80491BA, "esi", "reg_str_enc_flag");
	define_local_var(0X804918B, 0X80491BA, "edi", "reg_key");
	add_func    (0X80491BA,0X80491DE);
	set_func_flags(0X80491BA,0x4410);
	set_frame_size(0X80491BA, 0, 4, 0);
	add_func    (0X80491DE,0X80491EA);
	set_func_flags(0X80491DE,0x401);
	add_func    (0X804B14C,0X804B150);
	set_func_flags(0X804B14C,0x4400);
	SetType(0X804B14C, "int puts(const char *s);");
	set_frame_size(0X804B14C, 0, 0, 0);
	add_func    (0X804B150,0X804B154);
	set_func_flags(0X804B150,0x4400);
	SetType(0X804B150, "size_t strlen(const char *s);");
	set_frame_size(0X804B150, 0, 0, 0);
}

//------------------------------------------------------------------------
// Information about functions

static Functions(void) {

	Functions_0();
}

//------------------------------------------------------------------------
// Information about segment registers

static SegRegs(void) {
	split_sreg_range(0X8048000,"es",0,3);
	split_sreg_range(0X8049000,"es",0XFFFFFFFF,3);
	split_sreg_range(0X8049030,"es",0XFFFFFFFF,3);
	split_sreg_range(0X804AF58,"es",0,3);
	split_sreg_range(0X804B000,"es",0XFFFFFFFF,3);
	split_sreg_range(0X804B014,"es",0XFFFFFFFF,3);
	split_sreg_range(0X804B148,"es",0XFFFFFFFF,3);
	split_sreg_range(0X804B14C,"es",0XFFFFFFFF,3);
	split_sreg_range(0X8048000,"ss",0,3);
	split_sreg_range(0X8049000,"ss",0XFFFFFFFF,3);
	split_sreg_range(0X8049030,"ss",0XFFFFFFFF,3);
	split_sreg_range(0X804AF58,"ss",0,3);
	split_sreg_range(0X804B000,"ss",0XFFFFFFFF,3);
	split_sreg_range(0X804B014,"ss",0XFFFFFFFF,3);
	split_sreg_range(0X804B148,"ss",0XFFFFFFFF,3);
	split_sreg_range(0X804B14C,"ss",0XFFFFFFFF,3);
	split_sreg_range(0X8048000,"ds",0X8,3);
	split_sreg_range(0X8049000,"ds",0X8,3);
	split_sreg_range(0X8049030,"ds",0X8,3);
	split_sreg_range(0X804AF58,"ds",0X8,3);
	split_sreg_range(0X804B000,"ds",0X8,3);
	split_sreg_range(0X804B014,"ds",0X8,3);
	split_sreg_range(0X804B148,"ds",0XFFFFFFFF,3);
	split_sreg_range(0X804B14C,"ds",0XFFFFFFFF,3);
	split_sreg_range(0X8048000,"fs",0,3);
	split_sreg_range(0X8049000,"fs",0XFFFFFFFF,3);
	split_sreg_range(0X8049030,"fs",0XFFFFFFFF,3);
	split_sreg_range(0X804AF58,"fs",0,3);
	split_sreg_range(0X804B000,"fs",0XFFFFFFFF,3);
	split_sreg_range(0X804B014,"fs",0XFFFFFFFF,3);
	split_sreg_range(0X804B148,"fs",0XFFFFFFFF,3);
	split_sreg_range(0X804B14C,"fs",0XFFFFFFFF,3);
	split_sreg_range(0X8048000,"gs",0,3);
	split_sreg_range(0X8049000,"gs",0XFFFFFFFF,3);
	split_sreg_range(0X8049030,"gs",0XFFFFFFFF,3);
	split_sreg_range(0X804AF58,"gs",0,3);
	split_sreg_range(0X804B000,"gs",0XFFFFFFFF,3);
	split_sreg_range(0X804B014,"gs",0XFFFFFFFF,3);
	split_sreg_range(0X804B148,"gs",0XFFFFFFFF,3);
	split_sreg_range(0X804B14C,"gs",0XFFFFFFFF,3);
}

//------------------------------------------------------------------------
// Information about all patched bytes:

static Patches(void) {
}

//------------------------------------------------------------------------
// Call all byte feature functions:

static Bytes(void) {
	Bytes_0();
        end_type_updating(UTP_STRUCT);
}

// End of file.
