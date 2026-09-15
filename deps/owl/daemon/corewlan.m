/*
 * OWL: an open Apple Wireless Direct Link (AWDL) implementation
 * Copyright (C) 2018  The Open Wireless Link Project (https://owlink.org)
 * Copyright (C) 2018  Milan Stute
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreWLAN/CWInterface.h>
#import <CoreWLAN/CWChannel.h>
#import <net/if.h>

/*
 * Interfaces are obtained through +[CWInterface interfaceWithName:] rather than
 * CWWiFiClient, which arrived in 10.10. The collection is a bare NSSet because
 * Objective-C lightweight generics postdate the 10.9-era compiler.
 */
static struct wlan_state {
	CWInterface *iface;
	NSSet *supportedChannels;
	NSMutableDictionary *workingChannels;
} state;

/* Resolves and caches the CWInterface for ifindex. Returns nil on failure. */
static CWInterface *wlan_interface(int ifindex) {
	if (!state.iface) {
		char iface_cstr[IFNAMSIZ];
		const char *name = if_indextoname(ifindex, iface_cstr);
		if (!name)
			return nil;
		state.iface = [[CWInterface interfaceWithName:
			[NSString stringWithUTF8String:name]] retain];
	}
	return state.iface;
}

int corewlan_init() {
	state.iface = NULL;
	state.supportedChannels = NULL;
	state.workingChannels = [[NSMutableDictionary alloc] init];
	return 0;
}

void corewlan_free() {
	[state.workingChannels release];
	state.workingChannels = NULL;
	[state.supportedChannels release];
	state.supportedChannels = NULL;
	[state.iface release];
	state.iface = NULL;
}

int corewlan_disassociate(int ifindex) {
	CWInterface *iface = wlan_interface(ifindex);
	if (!iface)
		return -1;
	[iface disassociate];
	return 0;
}

int corewlan_get_channel(int ifindex) {
	@autoreleasepool {
	CWInterface *iface = wlan_interface(ifindex);
	return iface ? (int)[[iface wlanChannel] channelNumber] : 0;
	}
}

int corewlan_set_channel(int ifindex, int channel) {
	@autoreleasepool {
	CWInterface *iface = wlan_interface(ifindex);
	if (!iface)
		return -1;
	if (!state.supportedChannels)
		state.supportedChannels = [[iface supportedWLANChannels] retain];

	if (channel < 0)
		return -1;

	/* Reuse a width this driver has actually accepted. In particular, avoid
	 * repeating rejected 2.4 GHz 40 MHz requests on every social-channel hop.
	 * A later failure invalidates the cache and retries the other widths. */
	NSNumber *channelKey = [NSNumber numberWithInt:channel];
	CWChannel *cached = [[[state.workingChannels objectForKey:channelKey] retain] autorelease];
	if (cached) {
		NSError *err = nil;
		if ([iface setWLANChannel:cached error:&err] && !err)
			return 1;
		[state.workingChannels removeObjectForKey:channelKey];
	}

	/*
	 * Widest first, then progressively narrower. The card advertises 40MHz
	 * variants in the 2.4GHz band that it subsequently refuses to select with
	 * "Operation not supported", so committing to the widest match outright
	 * makes channel 6 unreachable. Falling back keeps the wide 5GHz channels
	 * that AWDL wants while still allowing 20MHz on 2.4GHz.
	 */
	int width, found_any = 0;
	NSError *last_err = nil;
	int last_width = 0;

	for (width = kCWChannelWidth160MHz; width >= kCWChannelWidth20MHz; width--) {
		for (CWChannel* chan in state.supportedChannels) {
			if (chan == cached)
				continue;
			if ([chan channelNumber] != (NSUInteger) channel)
				continue;
			if ([chan channelWidth] != (CWChannelWidth) width)
				continue;

			found_any = 1;
			NSError* err = nil;
			BOOL selected = [iface setWLANChannel:chan error:&err];
			if (selected && !err) {
				[state.workingChannels setObject:chan forKey:channelKey];
				return 1;
			}
			last_err = err;
			last_width = width;
		}
	}

	/*
	 * Callers ignore this return value, so report here: a channel change that
	 * quietly fails leaves the card listening on the wrong frequency and looks
	 * identical to there being no peers around.
	 */
	if (!found_any)
		fprintf(stderr, "corewlan: channel %d is not in the supported set\n", channel);
	else
		fprintf(stderr, "corewlan: failed to set channel %d (last tried width %d): %s\n",
			channel, last_width,
			last_err ? [[last_err localizedDescription] UTF8String] : "unknown error");
	return 0;
	}
}

int corewlan_get_hostname(char *name, size_t len) {
	NSString *computerName = [(NSString *) SCDynamicStoreCopyComputerName(NULL, NULL) autorelease];
	const char *utf8 = computerName ? [computerName UTF8String] : NULL;
	if (!utf8)
		return -1;
	strlcpy(name, utf8, len);
	return 0;
}
