#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/* ---------- Project 2 ---------- */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "kernel/stdio.h"
#include "threads/palloc.h"
/* ------------------------------- */
#include "vm/vm.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* ---------- Project 2 ---------- */
struct page *check_address (const uint64_t *user_addr);
static void check_valid_buffer (void *buffer, unsigned size, bool is_write_to_buffer);

void halt (void);			/* 구현 완료 */
void exit (int status);		/* 구현 완료 */
tid_t fork (const char *thread_name, struct intr_frame *f);
int exec (const char *cmd_line);
int wait (tid_t child_tid UNUSED); /* process_wait()으로 대체 필요 */
bool create (const char *file, unsigned initial_size); 	/* 구현 완료 */
bool remove (const char *file);							/* 구현 완료 */
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
/* ------------------------------- */
void *mmap (void *addr, long long length, int writable, int fd, off_t offset);
void munmap (void *addr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	/* ----------project 2----------- */
	lock_init(&file_rw_lock);
	/* ------------------------------ */

}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call! rax : %d\n", f->R.rax);
	// thread_exit ();

#ifdef VM
	thread_current()->user_rsp = f->rsp;
#endif

	/* ---------- Project 2 ---------- */
	switch(f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			if (f->R.rax == -1)
				exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi,f->R.rsi,f->R.rdx,f->R.r10,f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
			break;
		default:
			exit(-1);
			break;
	}
	/* ------------------------------- */
}

/* ---------- Project 2 ---------- */
struct page *check_address (const uint64_t *user_addr) {
	if (user_addr == NULL || is_kernel_vaddr(user_addr)) {
		exit(-1);
	} else {
		struct page *page = spt_find_page(&thread_current()->spt, user_addr);
		if (page == NULL) {
			exit(-1);
		} else {
			return page;
		}
	}
}

static void check_valid_buffer (void *buffer, unsigned size, bool is_write_to_buffer) {
	for (uint64_t uaddr = (uint64_t)buffer ; uaddr < (uint64_t)buffer + size; uaddr += PGSIZE) {
		struct page *page = check_address(uaddr);
		if (is_write_to_buffer == true && page->writable == false) {
			exit(-1);
		}
	}
}

int add_file_to_fdt(struct file *file) {
	struct thread *curr = thread_current();
	struct file **fdt = curr->fd_table;

	while (curr->fd_idx < FDCOUNT_LIMIT && fdt[curr->fd_idx]) {
		curr->fd_idx++;
	}

	if (curr->fd_idx >= FDCOUNT_LIMIT) {
		return -1;
	}

	fdt[curr->fd_idx] = file;
	return curr->fd_idx;
}

static struct file *get_file_from_fd_table(int fd) {
	struct thread *curr = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}
	return curr->fd_table[fd];
}

void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fd_table[fd] = NULL;
}

void 
halt (void) {
	power_off();
}

void exit(int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	char *save_ptr;
	
	strtok_r(curr->name, " ",&save_ptr);
	printf("%s: exit(%d)\n",curr->name,curr->exit_status);
	thread_exit();
}

tid_t fork (const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

int
exec(const char *cmd_line) {
	check_address(cmd_line);

	char *cmd_line_cp;
	int size = strlen(cmd_line)+1;
	cmd_line_cp = palloc_get_page(PAL_ZERO);
	if (cmd_line_cp == NULL) {
		exit(-1);
	}
	strlcpy (cmd_line_cp, cmd_line, size);

	if (process_exec(cmd_line_cp) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

bool 
create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool 
remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);

	if (open_file == NULL) {
		return -1;
	}
	
	int fd = add_file_to_fdt(open_file);

	if (fd == -1) {
		file_close(open_file);
	}
	return fd;
}

int
filesize (int fd) {
	struct file *open_file = get_file_from_fd_table(fd);
	
	if (open_file == NULL) {
		return -1;
	}
	return file_length(open_file);
}

int
read (int fd, void *buffer, unsigned size) {

	if (fd == 1) {
		return -1;
	}

	check_valid_buffer(buffer, size, true);

	int read_result_size;
	struct file *file_obj = get_file_from_fd_table(fd);


	/* fd = STDIN = 0 */
	if (fd == 0) {
		
		/* try 1 */
		int i;
		unsigned char *buf = buffer;
		for (i = 0; i < size; i++) {
			char c = input_getc();
			*buf++ = c;
			if (c == '\0')
				break;
		}

		read_result_size = i;
	}

	/* other file fd */
	else {
		if (file_obj == NULL) {
			return -1;
		} 
		else {
			// lock_acquire(&file_rw_lock);
			read_result_size = file_read(file_obj, buffer, size);
			// lock_release(&file_rw_lock);
		}
	}

	return read_result_size;
}

int
write (int fd, const void *buffer, unsigned size) {

	if (fd == 0) {
		return -1;
	}

	check_valid_buffer(buffer, size, false);

	int write_result_size;
	struct file *file_obj = get_file_from_fd_table(fd);
	
	/* fd = STDOUT = 1 */
	if (fd == 1) {
		putbuf(buffer, size);		/* to print buffer strings on the display*/
		write_result_size = size;
	}

	/* other file fd */
	else {
		if (file_obj == NULL) {
			write_result_size = -1;
		}
		else {
			// lock_acquire(&file_rw_lock);
			write_result_size = file_write(file_obj, buffer, size);
			// lock_release(&file_rw_lock);
		}
	}

	return write_result_size;
}

void
seek (int fd, unsigned position) {
	struct file *file_obj = get_file_from_fd_table(fd);

	if (fd <= 1 || file_obj == NULL) {
		return;
	}
	
	file_seek(file_obj, position);
}

unsigned
tell (int fd) {
	struct file *file_obj = get_file_from_fd_table(fd);

	if (fd <= 1 || file_obj == NULL) {
		return;
	}
	
	return file_tell(file_obj);	
}

void
close (int fd) {
	struct file *file_obj = get_file_from_fd_table(fd);

	if (fd<=1 || file_obj == NULL) {
		return;
	}
	
	remove_file_from_fdt(fd);
	file_close(file_obj);
}
/* ------------------------------- */

void *mmap (void *addr, long long length, int writable, int fd, off_t offset){
	if (pg_ofs(addr) != 0 || addr == NULL || is_kernel_vaddr(addr) || length <= 0){
		return NULL;
	}
	
	struct file* mapping_file = get_file_from_fd_table(fd);
	if (fd <= 1 || mapping_file == NULL || file_length(mapping_file) == 0){
		return NULL;
	}

	if (offset%PGSIZE != 0){
		return NULL;
	}

	return do_mmap(addr, length, writable, mapping_file, offset);
}

void munmap (void *addr){
	if (addr == NULL || is_kernel_vaddr(addr)) {
		exit(-1);
	}
	do_munmap(addr);
}