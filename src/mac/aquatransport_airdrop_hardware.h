#ifndef AQUATRANSPORT_AIRDROP_HARDWARE_H
#define AQUATRANSPORT_AIRDROP_HARDWARE_H
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include "aquatransport_airdrop_policy.h"
/* No CFSTR constants: the universal engine deliberately lazy-links CF. */
static CFTypeRef aq_registry_property(CFTypeRef (*copy)(io_registry_entry_t,CFStringRef,CFAllocatorRef,IOOptionBits),io_registry_entry_t entry,const char *name) {
    CFStringRef key=CFStringCreateWithCString(NULL,name,kCFStringEncodingUTF8);
    if(!key) return NULL;
    CFTypeRef value=copy(entry,key,NULL,0); CFRelease(key); return value;
}
static int hardware_supported(char *interface,size_t capacity) {
    /* Resolve IOKit only at ordinary runtime, and only in eligible sharingd. */
    void *kit=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);
    if(!kit) return 0;
    CFMutableDictionaryRef (*matching)(const char *)=dlsym(kit,"IOServiceMatching");
    kern_return_t (*services)(mach_port_t,CFDictionaryRef,io_iterator_t *)=dlsym(kit,"IOServiceGetMatchingServices");
    io_object_t (*next)(io_iterator_t)=dlsym(kit,"IOIteratorNext");
    kern_return_t (*release)(io_object_t)=dlsym(kit,"IOObjectRelease");
    CFTypeRef (*property)(io_registry_entry_t,CFStringRef,CFAllocatorRef,IOOptionBits)=dlsym(kit,"IORegistryEntryCreateCFProperty");
    int found=0,bluetooth=0; io_iterator_t iterator=0;
    if(!matching || !services || !next || !release || !property) goto done;
    if(services(0,matching("IO80211Interface"),&iterator)) goto done;
    io_object_t item;
    while((item=next(iterator))) {
        /* IO80211Interface establishes Wi-Fi capability, independent of vendor,
         * PCI identity or driver subclass. Never guess among multiple radios. */
        CFTypeRef name=aq_registry_property(property,item,"BSD Name");
        if(name && CFGetTypeID(name)==CFStringGetTypeID() &&
           CFStringGetCString(name,interface,capacity,kCFStringEncodingUTF8) &&
           aq_airdrop_interface_supported(interface)) found++;
        if(name) CFRelease(name);
        release(item);
    }
    release(iterator);
    iterator=0;
    if(!services(0,matching("IOBluetoothHCIController"),&iterator)) {
        while((item=next(iterator))) {
            CFTypeRef features=aq_registry_property(property,item,"HCISupportedFeatures");
            CFTypeRef connected=aq_registry_property(property,item,"BluetoothTransportConnected");
            if(features && CFGetTypeID(features)==CFDataGetTypeID() &&
               connected && CFGetTypeID(connected)==CFBooleanGetTypeID() && CFBooleanGetValue(connected) &&
               aq_airdrop_bluetooth_supported(CFDataGetBytePtr(features),(unsigned)CFDataGetLength(features))) bluetooth++;
            if(features) CFRelease(features); if(connected) CFRelease(connected);
            release(item);
        }
        release(iterator);
    }
done:
    dlclose(kit); return found==1 && bluetooth==1;
}
#endif
