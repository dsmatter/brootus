#include <linux/random.h>

#include "load_magic.h"

/*
 * Indicator if the module is still loaded
 *(This is used if the blocking call to the original read function returns
 * after this module was unloaded)
 */
int MAGIC;
int magic_status;

void init_load_magic(void)
{
  // Setup the magic numbers
  get_random_bytes(&MAGIC, sizeof(MAGIC));
  magic_status = MAGIC;
}

void unset_magic(void)
{
  // Remove the magic from the loading state indicator
  magic_status = 0;
}

int check_load_magic(void)
{
  return MAGIC == magic_status;
}

