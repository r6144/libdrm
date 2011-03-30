#ifndef MMAP_MANAGER_H
#define MMAP_MANAGER_H

#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

void *new_mmap_manager(void);
void free_mmap_manager(void *pman);
void *mmap_manager_map(void *pman, size_t len, int prot, int flags, int fd, off_t offset);
void mmap_manager_unmap(void *pman, void *addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
