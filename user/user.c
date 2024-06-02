#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEVICE_NAME "/dev/ref_monitor"

int main(int argc, char *argv[]) {
    int fd;
    ssize_t ret;
    char buffer[2048];

    if (argc != 3) {
        printf("Usage: %s <command> <parameter>\n", argv[0]);
        return -1;
    }

    snprintf(buffer, sizeof(buffer), "%s:%s", argv[1], argv[2]);

    fd = open(DEVICE_NAME, O_WRONLY);
    if(fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    ret = write(fd, buffer, strlen(buffer));
    if(ret < 0) {
        perror("Failed to write the message to the device");
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}