# Modern AirDrop on Mavericks

AquaTransport adapts Mavericks' original `sharingd` to modern AirDrop. Finder keeps its native discovery, acceptance, progress, file extraction, destination placement, conflicts and errors. The adapter changes transport and protocol metadata; it does not parse transfer archives. No SIMBL or Python runtime is required. TLS uses AquaTransport's existing OpenSSL engine and the native Keychain identity.

## Compatibility

Activation requires all of the following:

- Darwin 13, x86_64 `/usr/libexec/sharingd`, UUID `C4FA4877-6F18-3715-A5C8-DEDF9026BDF9` (the validated 10.9.5 binary).
- `/dev/tap0` present as a character device.
- Exactly one usable `IO80211Interface` with a BSD interface name; no vendor, PCI ID or driver-model whitelist.
- Exactly one connected Bluetooth controller with LE support.
- Root-owned module, helper, launchd job, radio executables and safe ancestor directories.
- No `disable-airdrop` entry in AquaTransport's `config/flags.txt`.

Required native symbols, methods, encodings and ownership are checked before hooks are installed. Unsupported systems retain their original AirDrop behavior. The universal loader has no new Foundation or IOKit linkage; the independent Objective-C module targets 10.9 only. It loads before SharingDaemon starts, outside the universal loader's constructor. Wi-Fi models are intentionally open to tester feedback. Multiple Wi-Fi interfaces remain ineligible because this adapter cannot safely choose which radio to take over.

The radio helper is socket-activated only on Mavericks. It independently checks hardware, TAP and the current console user. Its commands cannot specify executable paths or arbitrary arguments. Missing dependencies or startup failure unwind radio ownership gracefully. Before taking the radio, the helper checks CoreWLAN access and support for the configured channel 149. OWL then requires monitor-mode activation and radiotap capture; failure stops the radio processes and restores the Wi-Fi lease. Passing these capability checks does not establish successful AWDL communication on an untested card.

## Wi-Fi and transfer lifetime

Opening native AirDrop acquires the radio, disconnects ordinary Wi-Fi and starts OWL and Bluetooth advertising. Browser, receiver and transfer operations own independent leases. Navigating away cannot release the radio while a send or receive still owns it. Incoming transfers retain their native receiver until completion, cancellation or failure; deferred receiver shutdown uses the original stop method. Reopening cancels pending shutdown.

After the final owner releases its lease, a three-second grace period accommodates native object handoffs. The helper restores the previous Wi-Fi association when appropriate without retrieving passwords. A 15-second heartbeat renews the helper's 45-second lease; console-user changes and radio-process exits also trigger cleanup. Failed heartbeats reacquire ownership while native owners remain alive.

## Protocol and reliability

Modern `/Discover` metadata populates native Bonjour peers. Scoped IPv6 connections are limited to known AirDrop endpoints on TAP. The native sender creates the metadata and archive; the adapter adds modern offer fields and the matching upload header.

An accepted `/Ask` keeps its HTTP connection for `/Upload`, preserving Mavericks' native acceptance state. At receive completion, the adapter closes the consumed native input stream after BOM extraction returns, within the native adaptive receive call. This releases a producer join that otherwise waits for more body data. Native extraction status, placement and final response remain responsible for success or failure.

EOF delivery is idempotent per native connection/stream open. This addresses concurrent offer parsing seen in a native crash; duplicate EOF as that crash's exact cause remains an inference. Offline tests exercise the guard without reproducing the native crash.

OWL adopts master schedule changes immediately, retains clock mapping across bounded capture delays and checks the actual multicast transmit channel. Normal RSSI admission filtering prevents weak timing peers from taking over. Each radio session gets a new service-update identifier. Active native publishers reconfirm their own service-list PTR after three seconds, every five seconds during the first minute and every thirty seconds thereafter. This recovered a captured missing-recipient case without restarting the receiver or radio. Publication checks stop with their owner.

## Build, install and remove

Run `./build-macos.sh` for the complete payload. It calls `tools/build-airdrop.sh`, which can also rebuild the independent AirDrop payload alone. OWL and pinned libev sources are vendored; their source archives and license notices accompany the binaries. No development checkout or `/usr/local` runtime dependency is required.

`sudo ./install-macos.sh install` installs the complete staged build, including the socket helper. The Packages project also includes the AirDrop payload and uses its existing postinstall for helper setup during installation and updates. The single shipped `Uninstall.command` directly unloads/removes the helper, restores Security.framework and removes AquaTransport. No install or uninstall script is installed in `/usr/share`. Installation or updates can end an active transfer; perform them while AirDrop is idle.

Setting `disable-airdrop` and restarting sharingd disables activation while retaining the files.

The development Mac now runs through AquaTransport alone. The former ModernAirDrop SIMBL bundle and helper were moved out of their load locations; rollback copies and diagnostic evidence are retained separately.

## Validation and limits

On the development Mac, the user confirmed native transfers in both directions with an iPhone 13 mini running iOS 26.6.2, repeated discovery after closing/reopening AirDrop, and successful operation after the transfer-lifetime fix. The last live transfer retained its radio lease from 19:52:01 until 19:54:33 on September 14, 2026. Temporary packet capture and buffer monitoring were stopped after validation.

Offline regression scripts under `tools/test-airdrop-*.sh` cover clock delay, master scheduling, multicast scheduling, peer filtering, service-session identity, publication/EOF lifetimes, native receive stream completion and transfer ownership. The receive fixture exercises real CFHTTPServer/BOM through AquaTransport TLS with an open-ended body; its producer models the native adaptive lifetime, not the native codec. Transfer tests cover navigation, parallel operations, completion, cancellation, errors, abandoned operations, receiver reopening and helper failure.

Hardware eligibility is capability-based; this is not a validated compatibility claim for every legacy Mac. Additional hardware and actual 10.6/10.7/10.8 hosts have not been tested during this migration. The full TLS selftest requires an unpatched Security.framework and was not run on this already-patched host. Transfer throughput remains limited by this radio implementation; occasional offer latency is not fully explained. Longer use may expose additional lifecycle issues.
