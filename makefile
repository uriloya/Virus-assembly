virus: task3.o
	ld -m elf_i386 task3.o -o virus
	
task3.o: task3.s
	nasm -f elf task3.s -o task3.o

clean:
	rm -f *.o virus