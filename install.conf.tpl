DRIVE1 /dev/sda
SWRAID 0
BOOTLOADER grub
HOSTNAME __HOSTNAME__
PART /boot ext4 1G
PART lvm vg0 all crypt
LV vg0 swap swap swap 4G
LV vg0 root / xfs all
IMAGE __IMAGE__
CRYPTPASSWORD __PASSWORD__
