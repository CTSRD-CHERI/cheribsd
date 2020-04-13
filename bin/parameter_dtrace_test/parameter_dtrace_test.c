#include <stdio.h>

int simple(int a){
	printf("a = %d",a);
	return 6 * 7;
}
int only_cap(int * a){
	printf("a = %d",*a);
	return 6 * 7;
}
int both(int a, int * b){
	printf("a = %d, b = %d",a, *b);
	return 6 * 7;
}
int many(
    int *p1,
    int *p2,
    int *p3,
    int *p4,
    int *p5,
    int *p6,
    int *p7,
    int *p8,
    int *p9,
    int *p10,
    int *p11,
    int *p12
    )
{
	printf(
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       ,*p1,
	       *p2,
	       *p3,
	       *p4,
	       *p5,
	       *p6,
	       *p7,
	       *p8,
	       *p9,
	       *p10,
	       *p11,
	       *p12);
}
int many_with_normal(
    int *p1,
    int *p2,
    int *p3,
    int *p4,
    int *p5,
    int normal,
    int *p6,
    int *p7,
    int *p8,
    int *p9,
    int *p10,
    int *p11,
    int *p12
)
{
	printf(
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"
	       "%d"

	    ,*p1,
	       *p2,
	       *p3,
	       *p4,
	       *p5,
	       *p6,
	       *p7,
	       *p8,
	       *p9,
	       *p10,
	       *p11,
	       *p12,
	    normal);
}
int
main(void)
{
	int a = 0xdeadbeef;
	simple(a);
	only_cap(&a);
	int b = 0xcafebabe;
	both(a,&b);

	many(
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a
	    );

	many_with_normal(
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a,
	    &a
	);
	return (0);
}
