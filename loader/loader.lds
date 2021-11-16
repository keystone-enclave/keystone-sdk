OUTPUT_ARCH("riscv")

ENTRY( _start )

SECTIONS
{
  . = 0x0;

  .text :
  {
    PROVIDE( _start = . );
    *(._start)
    *(*)
  }

}
