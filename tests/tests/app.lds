OUTPUT_ARCH( "riscv" )

ENTRY(_start)

SECTIONS 
{
  . = 0x00001000;
  .sdata : {
	__global_pointer$ = . + 0x800;
  }
  .text : {
    *(.text._start)
    *(.text._start_c)
    *(.text)
  }
  . = ALIGN(0x1000);
  .rodata : 
  { 
    *(.rdata)
    *(.rodata)
  }
  .data : { *(.data) }
  .bss : { *(.bss) }
  .debug : { *(.debug) }

  . = ALIGN(0x1000);
  .malloc_zone :
  {
    __malloc_start = .;
    . = . + 0x10000;
    __malloc_zone_stop = .;
  }
  _end = .;
}
