test:minimal-qemu.c
	gcc -o $@ $^ -Wall -g -lpthread -O1

clean:
	-rm -rf test
