#include <stdio.h>
#include <setjmp.h>
#include <libunwind.h>

jmp_buf env;

void test3() __attribute__((noreturn));

void test3()
{
    unw_context_t ctx;
    unw_getcontext(&ctx);

    unw_cursor_t cursor;
    int ret = unw_init_local(&cursor, &ctx);
    if (ret == UNW_ESUCCESS) {
        while (unw_step(&cursor) > 0) {
            unw_word_t val;
            unw_get_reg(&cursor, UNW_REG_IP, &val);
            printf("%p\n", (void *)val);
        }

        printf("\n");
    }

    longjmp(env, 1);
}

void test2()
{
    printf("test2()\n");
    test3();
}
void test1()
{
    printf("test1()\n");
    test2();
}

int main(int argc, char *argv[])
{
    if (setjmp(env) == 0) {
        test1();
    }

    return 0;
}
