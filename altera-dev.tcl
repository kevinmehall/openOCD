source [find ./tcl/interface/altera-usb-blaster.cfg]
usb_blaster pin6 1
usb_blaster pin8 1
source [find ./tcl/target/vjtag.cfg]

proc fpga_test_init {} {
    
    
}

gdb_port 50001

init
#echo "Halting processor"
halt

foreach name [target names] {
    set y [$name cget -endian]
    set z [$name cget -type]
    puts [format "Chip is %s, Endian: %s, type: %s" \
                  $name $y $z]
}

