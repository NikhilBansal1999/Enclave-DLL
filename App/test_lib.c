#include <stdio.h>
int a=0,b=1,n=2;
int add(int c1,int c2)
{
  return c1+c2;
}
int loop(int num)
{
  while(n<num)
  {
    n++;
    b=add(b,a);
    a=b-a;
  }
}

int fibonacci(int num)
{
    //int a=0,b=1,n=2;
    if(num<=0)
    {
      return -1;
    }
    else if(num==1)
    {
      return 0;
    }
    else if(num==2)
    {
      return 1;
    }
    else
    {
      loop(num);
      return b;
    }
}
