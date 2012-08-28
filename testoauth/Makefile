all:
	gcc -ggdb -lssl -loauth -lcurl -o test.out test.c 
	rm -rf test.out.dSYM
debug:
	gcc -ggdb -DSAMUEL_DEBUG -lssl -loauth -lcurl -o test.out test.c 
	rm -rf test.out.dSYM
clean:
	rm test.out 
