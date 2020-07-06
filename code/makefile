DIR = $(shell mkdir Scores)

CC =gcc
CFLAGS =

.PHONY: main clean


main: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	echo $(DIR)
clean:
	rm main
