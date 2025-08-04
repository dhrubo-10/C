#include "cs50.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

int main() {
    int a = 5;

    int s[] = {5, 6, 10, 2, 1, 7, 3, 8, 4, 9, 12 ,11, 13, 20, 69, 59, 15, 14,
    65, 96, 21, 35, 46, 74,  21, 60, 54};
    int n = sizeof(s) / sizeof(s[0]);

    qsort(s, n, sizeof(int), compare);

    int found = 0;  // Variable to track whether the element is found or not

    for (int i = 0; i < n; i++) {
        if (a == s[i]) {
            printf("Found %d\n", a);
            found = 1;  // Set found to true
            break;
        }
    }

    if (!found) {
        printf("Not found %d\n", a);
    }

    return 0;
}
