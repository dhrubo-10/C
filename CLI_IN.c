/*
* Just a basic fun project on terminal i did few years back.
* Commented out things which helped me to understand and will
* help anyone to understand how terminal control works on linux.!
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

char *read_line(int time_o);

int main(int argc, char **argv)
{
	char *name;

	printf("N: ");
	fflush(stdout);
	name = read_line(3); /* giving 3 secs to get input. */

	if(name)
		printf("Hello %s\n", name);
	else
		printf("Timeout\n");

	return 0;
}

char *read_line(int time_o)
{
	static char buff[512]; /* A static local variable means it stays in memory even after the function returns.*/
	fd_set rfds; 	/* This is a file descriptor set, select() allows your program to wait for I/O events 
					 * like keyboard input, socket data, etc. with a timeout.
	 				 * fd_set is a specefic variable type structure for the selected function 
	 				 */
	struct timeval tv;	/* ! search net fo this or "man 3 timeval" -> on linux terminal for more info.... */
	int ret; /* return val  */

	FD_ZERO(&rfds); /* This initializes the file descriptor set. */
	FD_SET(0, &rfds); /* Adds file descriptor 0 ( stdin) to the set. 
					   * so your program will be watching keyboard input. 
					   */

	/*struct timeval holds two values:
	* tv_sec -> seconds
	* tv_usec -> microseconds
	* So here, im like telling the system:
	* “Wait for user input (on stdin) for time_o seconds, then give up.”
	* This makes the program non-blocking.. it won’t hang forever waiting for input.
	*/

	tv.tv_sec = time_o;
	tv.tv_usec = 0;

	/*
	* select() parameters:
	* select(nfds, &readfds, &writefds, &exceptfds, &timeout);
	* nfds -> highest file descriptor number + 1.
	* Since stdin = file descriptor 0, we pass 1.
	* &rfds -> set of file descriptors to check for readability (like input available).
	* writefds, exceptfds -> not used here 0 as we KNOW NULL.
	* &tv -> how long to wait (the timeout i set above).
	*/

	ret = select(1, &rfds, 0, 0, &tv);

	/*
	* If ret > 0, it means something became “ready” before the timeout.
	* FD_ISSET(0, &rfds) checks if stdin (fd 0) is that ready descriptor.
	*/
	if(ret && FD_ISSET(0, &rfds))
	{
		memset(buff, 0, 512);	/* memset() clears the buffer so no old data remains. */
		ret = read(0, buff, 511);	/* read(0, buff, 511) reads up to 511 bytes from stdin into buff. */
		if (ret < 1) /* If read() returns < 1, no valid input was received .. return 0. */
			return 0;
		ret--;
		buff[ret] = 0; /* or it sets the last character in the buffer to '\0' to mark the end of the string. */

		return buff; /* returns the string */
	}
 	else			
 		return 0;	/* If no input arrived before the timeout -> return 0 (NULL pointer). */
}/* DOne Done done */
