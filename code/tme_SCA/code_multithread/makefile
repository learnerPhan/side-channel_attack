CC =gcc
LDFLAGS =-lm -pthread
CFLAGS =

.PHONY: dpaAttack cpaAttack clean

dpaAttack: dpa
	./dpa aes_traces_dpa.csv

dpa: dpa_threads.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

cpaAttack: cpa
	./cpa aes_traces_cpa.csv

cpa: cpa_threads.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm cpa dpa
