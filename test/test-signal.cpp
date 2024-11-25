#include <stdio.h>
#include <signal.h>
#include <memory.h>
#include <libunwind.h>

void test3() __attribute__((noreturn));

void signal_handler(int sig)
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
}

void test3()
{
    for ( ; ; ) {
        for (unsigned int i = 0; i < 1000; ++i) {
        }

        for (unsigned int i = 0; i < 1000; ++i) {
        }

        for (unsigned int i = 0; i < 1000; ++i) {
        }

        for (unsigned int i = 0; i < 1000; ++i) {
        }
    }
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
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;

    sigaction(SIGINT, &sa, 0);

    test1();
    return 0;
}
