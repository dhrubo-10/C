#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>

char *trl(int timeout)
{
	static char buf[512];
	fd_set rfds;
	struct timeval tv;
	int ret;

	struct termios oldt, newt;

	// Save current terminal attributes
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;

	// Disable canonical mode and echo
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	// Prepare file descriptor set
	FD_ZERO(&rfds);
	FD_SET(STDIN_FILENO, &rfds);

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);

	if (ret > 0 && FD_ISSET(STDIN_FILENO, &rfds))
	{
		memset(buf, 0, sizeof(buf));
		ret = read(STDIN_FILENO, buf, sizeof(buf) - 1);

		// Restore terminal settings before returning
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

		if (ret < 1)
			return NULL;

		buf[ret] = '\0';
		return buf;
	}
	else
	{
		// Restore terminal settings before returning
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		return NULL;
	}
}

int main()
{
	char *name;

	printf("N: ");
	fflush(stdout); // Flush prompt immediately

	name = trl(5);
	if (name)
		printf("\nGot: %s\n", name);
	else
		printf("\nNULL\n");

	return 0;
}
