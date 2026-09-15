#import <Foundation/Foundation.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc,char **argv) { @autoreleasepool {
    NSString *command=argc==2 ? [NSString stringWithUTF8String:argv[1]] : @"status";
    if(![@[@"status",@"start",@"stop",@"heartbeat"] containsObject:command]) return 2;
    int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0) return 3;
    struct sockaddr_un address; memset(&address,0,sizeof(address)); address.sun_len=sizeof(address); address.sun_family=AF_UNIX;
    strlcpy(address.sun_path,"/var/run/org.aquatransport.airdrop.sock",sizeof(address.sun_path));
    struct timeval timeout={10,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    int one=1; setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))) { perror("connect"); close(fd); return 4; }
    NSMutableData *request=[[NSJSONSerialization dataWithJSONObject:@{@"command":command} options:0 error:NULL] mutableCopy]; [request appendBytes:"\n" length:1];
    if(write(fd,request.bytes,request.length)!=(ssize_t)request.length) { close(fd); return 5; }
    NSMutableData *data=[NSMutableData data]; char byte;
    while(data.length<4096 && read(fd,&byte,1)==1) { if(byte=='\n') break; [data appendBytes:&byte length:1]; }
    close(fd); id reply=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if(![reply isKindOfClass:[NSDictionary class]]) return 6;
    puts([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
    return [reply[@"ok"] boolValue] ? 0 : 1;
} }
