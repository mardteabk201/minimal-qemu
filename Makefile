test:minimal-qemu.c
	gcc -o $@ $^ -Wall -g -lpthread -O0

clean:
	-rm -rf test
