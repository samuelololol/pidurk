JSON_C_DIR=/usr/local/Cellar/json-c/0.9
CFLAGS += -ggdb -Wall
LDFLAGS+= -lssl -loauth -lcurl 
CFLAGS += -I$(JSON_C_DIR)/include/json
LDFLAGS+= -L$(JSON_C_DIR)/lib -ljson

all:
	gcc $(CFLAGS) $(LDFLAGS) -o test.out test.c 
	gcc $(CFLAGS) $(LDFLAGS) -o jsontest.out jsontest.c
	rm -rf test.out.dSYM jsontest.out.dSYM
debug:
	gcc $(CFLAGS) $(LDFLAGS) -DSAMUEL_DEBUG -o test.out test.c 
	rm -rf test.out.dSYM
clean:
	rm -rf test.out jsontest.out test.out.dSYM jsontest.out.dSYM
