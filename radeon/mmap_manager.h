#ifndef MMAP_MANAGER_H
#define MMAP_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

void *new_mmap_manager(void);
void free_mmap_manager(void *pman);
  
#ifdef __cplusplus
}
#endif

#endif
