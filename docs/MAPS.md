# Calendar maps and travel times on Mavericks

AquaTransport includes adaptations of the user-supplied `MapsURLFix-2.m` and
`CalendarETAFix.m`. They work with the system's GeoServices framework; installing
Apple Maps is not a prerequisite. Both are enabled by default on OS X 10.9
(Darwin 13). Other OS versions keep their existing behavior.

Add `disable-maps-fixes` to `/usr/share/aquatransport/config/flags.txt` to turn both
off. Restart Calendar, CalendarAgent and its GeoServices helper after changing this flag. Removing
the line enables the fixes again. This flag is independent of `disable-icloud-gsa`.

## Map URLs

Five exact legacy hosts are recognized: `gspa35-ssl.ls.apple.com`,
`gspa21.ls.apple.com`, `gspa19.ls.apple.com`, `gspa12.ls.apple.com`, and
`gspa11.ls.apple.com`. Requests move to the corresponding `gspe*-ssl.ls.apple.com`
host over HTTPS. URL credentials and nonstandard ports are outside the adapter's
scope. The rewriter retains escaped path/query bytes, duplicate query parameters
and fragments, and removes obsolete `tk`, `mapkey`, `sid` and `accessKey` parameters.

The four non-35 hosts receive the session identifier and access key described in
the supplied source. The key uses a random 16-character suffix, an expiry 4,200
seconds in the future, SHA-256 and AES-256-CBC with PKCS#7 padding. Host 35 requires
only the URL change. Existing modern hosts remain untouched. This does not relax
TLS certificate verification. Locations and generated URLs are not logged by the
adapter, including when AquaTransport debugging is on.

The implementation uses AquaTransport's C URL rewrite hooks instead of adding a
buffering `NSURLProtocol`. That preserves the application's streaming, cancellation,
request bodies and response handling. Both CFURLConnection and raw CFHTTPMessage
creation are covered.

The hooks resolve callable CFNetwork originals with `dlsym`. Calling a lazy
binding stub captured by fishhook let Mavericks replace our hook after its first
use. GeoServices' later asynchronous tile requests then went to the retired
hostname and failed with `NSURLErrorDomain -1003`, leaving the preview blank.
Resolving the originals keeps the hooks installed for subsequent requests.

## Calendar ETA requests

The native `GEODirectionsRequest writeTo:` method writes legacy waypoints at
protobuf field 2. The supplied fix describes the replacement typed waypoints at
field 22. Location-backed waypoints retain the native GEOLocation message; entry
points become a coordinate waypoint. Latitude is averaged, and longitude uses a
circular mean so that points on opposite sides of the date line stay together.

AquaTransport serializes the original request into a temporary native writer,
replaces only its waypoints and preserves the other fields byte-for-byte. If no
maximum route count was supplied, it adds the sample's default of three. Unlike
the supplied replacement serializer, it retains departure time, rerouting options,
capabilities and other native fields. An unsupported waypoint, invalid coordinate,
malformed message or changed schema causes the whole request to use its native
serialization; stops are never silently removed. Buffers and waypoint counts are
bounded. Request/location data is not persisted by the adapter.

`Protobufs.h` and `GeoHeaders.h` were not supplied. The implementation uses the
installed framework's runtime interfaces and a small protobuf encoder/parser;
it does not require those headers or bundle Apple's frameworks.

## Loading, build and validation

`aquatransport_maps.dylib` is separate from authentication. It supports both i386
and x86_64, including Objective-C GC. The existing GC-capable compiler builds it.
The loader and TLS engine retain their existing minimum deployment targets.

A C dyld callback installs a trampoline only for Mavericks' native directions
serializer, without loading Foundation. A dlopen hook checks again after late
GeoServices loads, because ObjC classes are not registered at the first image
notification. The maps module loads only at an actual map URL or directions
serialization call. Existing non-native replacements of the serializer are left
alone. Ordinary C processes do not load Foundation through this mechanism.

Run `./build-macos.sh`, `./tools/maps-selftest.sh`, and
`./tools/gsa-selftest.sh`. Map tests use a catch-all URL protocol and native
GeoServices objects with synthetic coordinates. They verify URL scope, independent
decryption of generated access keys, escaped paths and duplicate parameters,
request-body/header preservation, repeated requests through GeoServices' private
asynchronous NSURLConnection initializer, raw CFHTTPMessage rewriting, startup and late
framework loading, both waypoint forms, date-line handling, preservation of other
route fields, native fallback, the off flag, and GC URL handling. A C process probe
checks that Foundation stays unloaded and fork still works.

The existing installer and package include the new module under
`/usr/share/aquatransport/`. No load command is added to Calendar, GeoServices or
its XPC executable. No installer resources are extracted or indexed.

**Status:** The user confirmed both Calendar's map preview and travel times work.
The blank-map failure
was reproduced with repeated asynchronous requests and a fixed public Manhattan
tile through the native GeoServices loader. After correcting the lazy binding
issue and restarting the map helper, that full tile-loader request succeeds. The
downloaded vector tile also decodes with the native decoder. All 21 offline map
checks and the existing authentication checks pass. The correction is installed
and the rendered Calendar preview is confirmed working after reopening the app.
