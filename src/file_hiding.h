#ifndef FILE_HIDING_H
#define FILE_HIDING_H

#include <linux/dirent.h>
#include "brootus.h"

// Define linux_dirent as in fs/readdir.c (line 135)
// (needed for getdents syscall)
struct linux_dirent {
  unsigned long   d_ino;
  unsigned long   d_off;
  unsigned short  d_reclen;
  char            d_name[1];
};

BROOTUS_MODULE(file_hiding);

extern void set_file_prefix(char* prefix);

#endif
