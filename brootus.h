#ifndef BROOTUS_MODULE_H
#define BROOTUS_MODULE_H

#define BROOTUS_MODULE(name) extern void init_##name(void); \
                             extern void finalize_##name(void); \
                             extern void enable_##name(void); \
                             extern void disable_##name(void);

#endif