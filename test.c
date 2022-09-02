#include <stdio.h>

void foobar(int input){
    int val = 10;
    int leet = 0x1337;
    int beet = 0xdeadbeef;
    val += input;
    beet += input;
    leet += val;
    printf("%d\n",val);
}

int main (int argc, char *argv[])
{
    int val = 10;
    printf("%d\n",val);
    puts("HELLO");
    foobar(val);
    return 0;
}

