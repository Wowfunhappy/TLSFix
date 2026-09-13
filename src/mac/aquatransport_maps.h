#ifndef AQUATRANSPORT_MAPS_H
#define AQUATRANSPORT_MAPS_H

/* Both return/accept C types so the engine remains free of ObjC dependencies. */
char *tf_maps_rewrite_url(const char *url);
void tf_maps_install(void);

#endif
