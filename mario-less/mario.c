#include <stdio.h>
#include <cs50.h>

int main()
{
    //initializing height as integer
    int height;

    do
    {
        //taking input for height
        height = get_int("Height: ");
    }while(height < 1 || height > 8 );
    //outer loop for rows..
    for(int i = 0; i < height; i++)
    {
        //inner loop for spaces..
        for(int s = 0; s < height - i - 1;s++)
        {
            printf(" ");
        }
        //printing #
        for(int j = 0;j <= i; j++)
        {
            printf("#");
        }
        //new line
        printf("\n");
    }
}

