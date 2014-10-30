handle SIGUSR1 nostop noprint
b main
run -m 1024 -L pc-bios -enable-kvm -drive if=virtio,file=test.qcow2,cache=none -cdrom /home/sandeep/iso/ubuntu14-04.iso -hdb ldb://localhost:1010 
#run -m 1024 -L pc-bios -enable-kvm -drive if=virtio,file=test.qcow2,cache=none -cdrom /home/sandeep/iso/ubuntu14-04.iso 
