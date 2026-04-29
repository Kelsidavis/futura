// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standard file descriptors */
#define STDIN_FILENO   0
#define STDOUT_FILENO  1
#define STDERR_FILENO  2

/* lseek whence values */
#define SEEK_SET  0
#define SEEK_CUR  1
#define SEEK_END  2

/* access(2) modes */
#define F_OK  0
#define R_OK  4
#define W_OK  2
#define X_OK  1

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int     close(int fd);
off_t   lseek(int fd, off_t offset, int whence);
int     pipe(int pipefd[2]);
int     pipe2(int pipefd[2], int flags);
int     dup(int oldfd);
int     dup2(int oldfd, int newfd);
int     dup3(int oldfd, int newfd, int flags);
int     unlink(const char *pathname);
int     unlinkat(int dirfd, const char *pathname, int flags);
int     access(const char *pathname, int mode);
int     faccessat(int dirfd, const char *pathname, int mode, int flags);

pid_t   fork(void);
pid_t   getpid(void);
pid_t   getppid(void);
uid_t   getuid(void);
uid_t   geteuid(void);
gid_t   getgid(void);
gid_t   getegid(void);
pid_t   getpgid(pid_t pid);
pid_t   setsid(void);
pid_t   getsid(pid_t pid);

int     chdir(const char *path);
int     fchdir(int fd);
char   *getcwd(char *buf, size_t size);

unsigned int sleep(unsigned int seconds);
int     usleep(unsigned int usec);

int     execv(const char *path, char *const argv[]);
int     execve(const char *path, char *const argv[], char *const envp[]);
int     execvp(const char *file, char *const argv[]);

int     ftruncate(int fd, off_t length);
int     truncate(const char *path, off_t length);

extern char **environ;

#ifdef __cplusplus
}
#endif
