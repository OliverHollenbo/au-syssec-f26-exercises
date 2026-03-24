#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((noreturn))
void exit_process(int exit_code);

ssize_t read_from_stdin(void *buf, size_t count);

ssize_t print_file(int fd, size_t count);

long matrix_read(long* matrix, size_t num_rows, size_t num_columns, size_t row, size_t column) {
    return matrix[row * num_columns + column];
}

void matrix_write(long* matrix, size_t num_rows, size_t num_columns, size_t row, size_t column, long value) {
    matrix[row * num_columns + column] = value;
}

long if_then_else(long a, long b, long c);

int get_correct_answer() {
    return 42;
}

bool is_correct(int answer) {
    if (answer == get_correct_answer()) {
        return true;
    } else{
        return false;
    }
}

void win() {
    printf("Nope!!!!!\n");
}

long get_mysterious_number() {
    return 50008;
}

const char* bin_sh = "/bin/sh";
char* null_pointer = NULL;
char data_array[1024] = {0};

void print_introduction() {
    printf("to execute a program (e.g., a shell), you can use the execve syscall\n");
    printf("- rax = 0x3b (syscall number)\n");
    printf("- rdi = <pointer to the command> (e.g., \"%s\")\n", bin_sh);
    printf("- rsi = <pointer to a NULL-terminated array of arguments> (e.g., pointer to a NULL pointer for no arguments)\n");
    printf("- rdx = <pointer to a NULL-terminated array of environment variables> (e.g., pointer to a NULL pointer for no arguments)\n");
    printf("useful values:\n");
    printf("- string \"%s\" at address %p\n", bin_sh, bin_sh);
    printf("- pointer \"%p\" at address %p\n", null_pointer, &null_pointer);
    printf("- readable/writable 1024 B array at address  %p\n", data_array);
}

void vuln() {
    printf("ROP me!\n");
    char buffer[32];
    ssize_t bytes_read = read_from_stdin(buffer, 3200);
    printf("read %zu bytes from standard input\n", bytes_read);
}

int main(int argc, char** argv) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    print_introduction();
    vuln();
    exit_process(0);
}
