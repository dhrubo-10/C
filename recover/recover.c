#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: ./recover FILE\n");
        return 1;
    }

    FILE *card = fopen(argv[1], "r");

    if (card == NULL)
    {
        printf("Not found\n");
        return 2;
    }

    uint8_t buffer[512];

    int count = 0;
    FILE *jpeg = NULL;

    char *name = malloc(8 * sizeof(char));

    while (fread(buffer, 1, 512, card))
    {
        if (buffer[0] == 0xff && buffer[1] == 0xd8 && buffer[2] == 0xff && (buffer[3] & 0xf0) == 0xe0)
        {
            if (count > 0)

            {

                fclose(jpeg);
            }

            sprintf(name, "%03i.jpg", count);

            jpeg = fopen(name, "w");
            count++;
        }
        if (jpeg != NULL)
        {
            fwrite(buffer, 1, 512, jpeg);
        }
    }
    free(name);
    fclose(jpeg);
    fclose(card);
}
