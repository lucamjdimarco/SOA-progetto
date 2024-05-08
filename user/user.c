#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "call.h"

int main(int argc, char *argv[]) {
    int value;

    if (argc < 2) {
        printf("Monitor OFF richiede la passwd\n");
        return -1;
    }

    value = monitor_OFF(argv[1]);

    if(value < 0) {
        printf("Errore nella monitor_OFF\n");
        return -1;
    } else {
        printf("Monitor OFF eseguito con successo\n");
        return 0;
    }

    return 0;

}