
test/test.out: test/main.c
	gcc $^ src/binary.c src/sha/* -o test/test.out -I include

clean:
	rm test/*.out
