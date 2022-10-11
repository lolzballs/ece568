#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ip_parser.h"

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
		return -1;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("open");
		return -1;
	}

	struct stat stat;
	int res = fstat(fd, &stat);
	if (res == -1) {
		perror("fstat");
		return -1;
	}

	uint8_t *buffer = malloc(stat.st_size);
	if (buffer == NULL) {
		fprintf(stderr, "malloc failed\n");
		return -1;
	}

	res = read(fd, buffer, stat.st_size);
	if (res == -1) {
		perror("read");
		return -1;
	}

	res = ip_parse(buffer, stat.st_size);
	printf("ip_parse returned %d\n", res);

	return 0;
}
