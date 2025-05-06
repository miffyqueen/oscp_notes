### Analysing ###
```
file <bin>  
strings -n8 <tfo bin> 
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out  
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple

#Using binwalk to determine the file structue and decompile the bin file
binwalk -e <bin> 

```
