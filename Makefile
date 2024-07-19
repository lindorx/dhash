
test/test.out: test/main.c
	gcc $^ src/binary.c src/sha/* src/sm/* src/ascon/* -o test/test.out -I include

clean:
	rm test/*.out
