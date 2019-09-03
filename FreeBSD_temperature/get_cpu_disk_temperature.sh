#!/usr/local/bin/bash

# A quick script to print system temperature info
#
# Tue Sep  3 11:36:56 PDT 2019
#
# Author: Peter Shipley

print_temp () {
    name=$1
    t_c=$2
    t_f=$(($t_c * 9/5 + 32))
    echo $name '	' $t_c 'C / ' ${t_f} 'F'
}



y=$(sysctl dev.cpu.0 | grep temperature | cut -w -f 2)
x="${y%.*}"
print_temp CPU0 $x

y=$(sysctl dev.cpu.0 | grep temperature | cut -w -f 2)
x="${y%.*}"
print_temp CPU1 $x

if [ -x /usr/local/sbin/smartctl ]; then

    for i in `sysctl kern.disks` ; do
	test -e "/dev/${i}" || continue

	x=$(smartctl -A /dev/${i} | grep -i temperature | cut -w -f 10)
	test -z "${x}" && continue
	print_temp ${i} ${x}
    done

fi

exit 0
