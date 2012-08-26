#include <stdio.h>
#include <string.h>

int main(int argc, char const* argv[])
{
    char a[128]={};
    scanf("%s",a);
    printf("%s\t%d\n",a,(int)strlen(a));
    return 0;
}
