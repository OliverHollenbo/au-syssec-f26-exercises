.intel_syntax noprefix                  # Because it is more beautiful.
.section .note.GNU-stack,"",@progbits   # We do not need nor want an executable stack.

.text

.global exit_process
.type exit_process, @function
exit_process:
mov rdi, 0x3c
mov rax, rdi
syscall


.global read_from_stdin
.type read_from_stdin, @function
read_from_stdin:
mov rdx, rsi
mov rsi, rdi
xor rdi, rdi
xor rax, rax
syscall
ret


prepare_print_file:
mov r10, rsi
mov rsi, rdi
mov rax, 0x28
xor rdi, rdi
mov rdx, rdi
inc rdi
ret

.global print_file
.type print_file, @function
print_file:
call prepare_print_file
syscall
ret


.global if_then_else
.type if_then_else, @function
if_then_else:
push rdi
push rsi
push rdx
call get_correct_answer
pop rdx
pop rsi
pop rdi
cmp rdi, rax
jne not_equal
mov rax, rsi
ret
not_equal:
mov rax, rdx
ret
