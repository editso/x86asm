#include "PEParser.h"
#include <stdio.h>

int main(int argc, char **argv) {

	PEParser pe;

	if (argc <= 1) {
		printf("usage:\n%s PE File\n", argv[1]);
    exit(0);
	}

	if (!pe.readPE(argv[1]) || !pe.initPE()) {
		return 0; 
	}

	pe.peInfo();



	return 0;

}