#include <final/final.h>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <stdio.h>

#define CODE "INC cx; DEC dx"

#define ADDRESS 0x1000

int main (int argc, char* argv[])
{
    ks_engine *ks;
      ks_err err;
      size_t count;
      unsigned char *encode;
      size_t sizecode;
  
      err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
      if (err != KS_ERR_OK) {
          printf("ERROR: failed on ks_open(), quit\n");
          return -1;
      }
  
      if (ks_asm(ks, CODE, 0, &encode, &sizecode, &count) != KS_ERR_OK) {
          printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
		         count, ks_errno(ks));
      } else {
          size_t i;
  
          printf("%s = ", CODE);
          for (i = 0; i < sizecode; i++) {
              printf("%02x ", encode[i]);
          }
          printf("\n");
          printf("Compiled: %lu bytes, statements: %lu\n", sizecode, count);
      }
      ks_free(encode);
      ks_close(ks);
      csh handle;
	cs_insn *insn;

	if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, encode, sizecode, ADDRESS, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
	
uc_engine *uc;
   uc_err error;
   int r_cx = 0x1234;
   int r_dx = 0x7890;
   int r_ip = 0x0000;
   printf("Emulate i386 code\n");
   error = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
   if (error != UC_ERR_OK) {
     printf("Failed on uc_open() with error returned: %u\n", error);
     return -1;
   }
   uc_mem_map(uc, ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL);
   if (uc_mem_write(uc, ADDRESS, encode, sizecode)) {
     printf("Failed to write emulation code to memory, quit!\n");
     return -1;
   }
   uc_reg_write(uc, UC_X86_REG_CX, &r_cx);
   uc_reg_write(uc, UC_X86_REG_DX, &r_dx);
   uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
   printf(">>> CX = 0x%x\n", r_cx);
   printf(">>> DX = 0x%x\n", r_dx);
   printf(">>> IP = 0x%x\n", r_ip);
   error=uc_emu_start(uc, ADDRESS, ADDRESS + sizecode, 0, 0);
   if (error) {
     printf("Failed on uc_emu_start() with error returned %u: %s\n",
       error, uc_strerror(error));
   }
   printf("Emulation done. Below is the CPU context\n"); 
   uc_reg_read(uc, UC_X86_REG_CX, &r_cx);
   uc_reg_read(uc, UC_X86_REG_DX, &r_dx);
   uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
   printf(">>> CX = 0x%x\n", r_cx);
   printf(">>> DX = 0x%x\n", r_dx);
   printf(">>> IP = 0x%x\n", r_ip);
   uc_close(uc);
  finalcut::FApplication app(argc, argv);
  finalcut::FDialog dialog(&app);
  dialog.setText ("A dialog");
  const finalcut::FPoint position{25, 5};
  const finalcut::FSize size{30, 10};
  dialog.setGeometry (position, size);
  finalcut::FWidget::setMainWidget(&dialog);
  dialog.show();
  return app.exec();
}
