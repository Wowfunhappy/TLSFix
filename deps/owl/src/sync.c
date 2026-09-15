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

#include "sync.h"
#include "ieee80211.h"

uint64_t awdl_rx_clock_time(struct awdl_rx_clock *clock, uint64_t hardware, uint64_t host) {
	if (!hardware || hardware > INT64_MAX || host > INT64_MAX)
		return host; /* Missing or invalid optional radiotap timestamp. */
	int64_t observed = (int64_t)host - (int64_t)hardware;
	if (!clock->initialized || (hardware < clock->last_hardware &&
	                           clock->last_hardware - hardware > 100000)) {
		clock->initialized = 1;
		clock->offset = observed;
		clock->last_hardware = hardware;
		return host; /* First sample, or the radio clock restarted. */
	}
	uint64_t distance = observed >= clock->offset ?
		(uint64_t)observed - (uint64_t)clock->offset :
		(uint64_t)clock->offset - (uint64_t)observed;
	if (distance > 100000) {
		/* A delayed capture batch can arrive more than 100 ms late. Using
		 * delivery time for that packet and mapped radio time for the next
		 * one creates a discontinuity in the advertised AWDL schedule.
		 * Preserve the established mapping for bounded positive latency,
		 * without teaching the estimator that queueing delay is clock drift.
		 * Implausible forward jumps and long clock outages retain fallback. */
		if (observed > clock->offset && distance <= 1000000) {
			if (hardware > clock->last_hardware)
				clock->last_hardware = hardware;
			return hardware + clock->offset;
		}
		return host;
	}
	int64_t change = observed - clock->offset;
	/* Delivery latency is positive: follow lower-latency samples quickly, but
	 * let the offset rise only slowly for clock drift. A measured 10 ms driver
	 * delivery stall must not shift the AWDL schedule by those same 10 ms. */
	clock->offset += change < 0 ? change / 4 : change / 1024;
	if (hardware > clock->last_hardware)
		clock->last_hardware = hardware;
	uint64_t corrected = hardware + clock->offset;
	return corrected < host ? corrected : host;
}

void awdl_sync_state_init(struct awdl_sync_state *state, uint64_t now) {
	state->last_update = now;
	state->aw_counter = 0;
	state->aw_period = 16;
	state->presence_mode = 4;

	state->meas_err = 0;
	state->meas_total = 0;
}

uint16_t awdl_sync_next_aw_tu(uint64_t now_usec, const struct awdl_sync_state *state) {
	uint64_t eaw_period = state->presence_mode * state->aw_period;
	uint64_t time_since = ieee80211_usec_to_tu(now_usec - state->last_update);
	uint64_t next_aw_tu = eaw_period - (time_since % eaw_period);
	return (uint16_t) next_aw_tu;
}

uint64_t awdl_sync_next_aw_us(uint64_t now_usec, const struct awdl_sync_state *state) {
	uint64_t eaw_period = ieee80211_tu_to_usec(state->presence_mode * state->aw_period);
	uint64_t time_since = now_usec - state->last_update;
	uint64_t next_aw_us = eaw_period - (time_since % eaw_period);
	return next_aw_us;
}

uint16_t awdl_sync_current_aw(uint64_t now_usec, const struct awdl_sync_state *state) {
	uint64_t eaw_period = state->presence_mode * state->aw_period;
	uint64_t time_since = ieee80211_usec_to_tu(now_usec - state->last_update);
	uint64_t current_aw = state->aw_counter + /* last counter */
	                      (time_since % eaw_period) / state->aw_period + /* within EAW */
	                      state->presence_mode * (time_since / eaw_period); /* correction for EAWs */
	return (uint16_t) current_aw;
};

uint16_t awdl_sync_current_eaw(uint64_t now_usec, const struct awdl_sync_state *state) {
	return (awdl_sync_current_aw(now_usec, state) / state->presence_mode);
}

int64_t awdl_sync_error_tu(uint64_t now_usec, uint16_t time_to_next_aw, uint16_t aw_counter,
                           const struct awdl_sync_state *state) {
	return ((aw_counter / state->presence_mode - awdl_sync_current_eaw(now_usec, state)) *
	        state->presence_mode * state->aw_period) -
	       (time_to_next_aw - awdl_sync_next_aw_tu(now_usec, state));
}

void awdl_sync_update_last(uint64_t now_usec, uint16_t time_to_next_aw, uint16_t aw_counter,
                           struct awdl_sync_state *state) {
	uint64_t eaw_period = state->presence_mode * state->aw_period;
	state->last_update = now_usec - ieee80211_tu_to_usec(eaw_period - time_to_next_aw);
	state->aw_counter = aw_counter & 0xfffc; /* mask last two bits, effectively 'aw_counter/4*4' */
}
