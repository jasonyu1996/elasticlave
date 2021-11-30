extern void __run_exit_handlers(int, void*, int, int) __attribute__((noreturn));

void exit(int status) __attribute__((noreturn));

void exit(int status) {
    int* dummy = 0;
    __run_exit_handlers(status, &dummy, 1, 0);
}

