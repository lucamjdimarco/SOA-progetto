#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEVICE_NAME "ref_monitor"

int main(int argc, char *argv[]) {

    int fd;
    ssize_t ret;

    if (argc != 2) {
        printf("Usage: %s <string>\n", argv[0]);
        return -1;
    }

    fd = open(DEVICE_NAME, O_WRONLY);
    if(fd < 0) {
        perror("Failed to open the device\n");
        return -1;
    }

    ret = write(fd, argv[1], strlen(argv[1]));

    if(ret < 0) {
        perror("Failed to write the message to the device\n");
        return -1;
    }

    close(fd);


    
    return 0;

}