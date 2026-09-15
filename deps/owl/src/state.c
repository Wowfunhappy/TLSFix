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

#include <time.h>
#include <string.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

#include "version.h"
#include "state.h"

#define ETHER_BROADCAST (struct ether_addr) {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}
#define PSF_INTERVAL_MASTER_TU 110
#define PSF_INTERVAL_SLAVE_TU 440

void awdl_init_state(struct awdl_state *state, const char *hostname, const struct ether_addr *self,
                     struct awdl_chan chan, uint64_t now) {
	/* A new radio session must invalidate cached services from the old one.
	 * Zero was previously sent forever, including after TAP/listener replacement.
	 * Keep this stable while running: changing every frame would flush caches
	 * continuously. This is a protocol generation, not a security token. */
#ifdef __APPLE__
	state->service_update_indicator = (uint16_t)(arc4random_uniform(65535) + 1);
#else
	state->service_update_indicator = (uint16_t)((now ^ (now >> 16)) % 65535 + 1);
#endif
	state->self_address = *self;
	strncpy(state->name, hostname, HOST_NAME_LENGTH_MAX);
	state->version = awdl_version(3, 4);
	state->dev_class = AWDL_DEVCLASS_MACOS;

	state->sequence_number = 0;
	state->psf_interval = PSF_INTERVAL_MASTER_TU;
	state->dst = ETHER_BROADCAST;

	state->tlv_cb = 0;
	state->tlv_cb_data = 0;

	state->peer_cb = 0;
	state->peer_cb_data = 0;

	state->peer_remove_cb = 0;
	state->peer_remove_cb_data = 0;

	state->filter_rssi = 1;
	state->rssi_threshold = RSSI_THRESHOLD_DEFAULT;
	state->rssi_grace = RSSI_GRACE_DEFAULT;

	awdl_sync_state_init(&state->sync, now);
	memset(&state->rx_clock, 0, sizeof(state->rx_clock));

	state->channel.enc = AWDL_CHAN_ENC_OPCLASS;
	state->channel.master = chan;
	state->channel.current = CHAN_NULL;
	//awdl_chanseq_init(state->channel.sequence);
	awdl_chanseq_init_static(state->channel.sequence, &state->channel.master);
	state->follow_master_chanseq = 0;
	state->have_preferred_peer = 0;
	memcpy(state->configured_sequence, state->channel.sequence,
	       sizeof(state->configured_sequence));

	awdl_election_state_init(&state->election, self);

	awdl_peer_state_init(&state->peers);

	awdl_stats_init(&state->stats);
}

void awdl_stats_init(struct awdl_stats *stats) {
	stats->tx_action = 0;
	stats->tx_data = 0;
	stats->tx_data_unicast = 0;
	stats->tx_data_multicast = 0;
	stats->rx_action = 0;
	stats->rx_data = 0;
	stats->rx_unknown = 0;
}

uint16_t awdl_state_next_sequence_number(struct awdl_state *state) {
	return state->sequence_number++;
};

void ieee80211_init_state(struct ieee80211_state *state) {
	state->qos_data = 0;
	state->sequence_number = 0;
	state->fcs = 0;
}

unsigned int ieee80211_state_next_sequence_number(struct ieee80211_state *state) {
	uint16_t seq = state->sequence_number;
	state->sequence_number += 1;
	state->sequence_number &= 0x0fff; /* seq has only 12 bits */
	return seq;
};

uint64_t clock_time_us() {
#ifdef __APPLE__
	/*
	 * clock_gettime(CLOCK_MONOTONIC) is only available from macOS 10.12, so the
	 * monotonic clock is read through the Mach timebase instead. The scaling is
	 * applied to the numerator first because on Intel the timebase is 1/1 and
	 * ticks are already nanoseconds; dividing first would quantise them away.
	 */
	static mach_timebase_info_data_t timebase;
	uint64_t ticks;

	if (timebase.denom == 0) {
		if (mach_timebase_info(&timebase) != KERN_SUCCESS)
			return 0;
	}

	ticks = mach_absolute_time();
	return (ticks * timebase.numer / timebase.denom) / 1000;
#else
	int result;
	struct timespec now;
	uint64_t now_us = 0;

	result = clock_gettime(CLOCK_MONOTONIC, &now);
	if (!result) {
		/* TODO why using 'long' for time? */
		now_us = now.tv_sec * 1000000;
		now_us += now.tv_nsec / 1000;
	}
	return now_us;
#endif
}
