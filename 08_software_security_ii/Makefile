CC = gcc
CFLAGS = -fno-stack-protector -no-pie

rop_me: rop_me.c lib.s
	$(CC) -o $@ $(CFLAGS) $^

rop_me_static: rop_me.c lib.s
	$(CC) -o $@ $^ -static
