#include "cheri_c_test.h"

union CallData {
  struct {
    char* c;
    int i;
    char* c2;
  } Bar;
};

__attribute__((noinline)) void f(union CallData foo) {
  char *d = foo.Bar.c;
  char *e = foo.Bar.c2;
  int j = foo.Bar.i;
  assert_eq(d[0], 'h');
  assert_eq(e[0], 'w');
  assert_eq(j, 9);
}

BEGIN_TEST(clang_purecap_union_struct)
  union CallData foo;
  foo.Bar.c = "hello";
  foo.Bar.i = 9;
  foo.Bar.c2 = "world";
  f(foo);
END_TEST
