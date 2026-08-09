# AquaTransport

AquaTransport fixes connection issues on Mac OS X 10.6 –&nbsp;10.9 by modifying how apps on your Mac talk to servers on the internet. Based on [TLSFix](https://github.com/ObscureMosquito/TLSFix), which was originally written for iOS by nfzerox and ObscureMosquito. Mac-specific code written by Claude Opus 5.

This package replaces my older Aqua Proxy package.



## Advanced Configuration

Advanced users can edit configuration files in /usr/share/aquatransport to change how apps talk to specific websites.

- redirects.txt — send traffic addressed to one URL to a different URL instead.
- headers.txt — set custom headers on traffic addressed to a URL.
- flags.txt — turn on optional behavior, one flag name per line.

Each file contains a set of rules separated by empty lines. The first line of each rule controls which app (technically executable name) the rule applies to. Can contain multiple names separated by commas. Use * for every app.

All URLs are "starts with" matches, and can contain * as a wildcard.

### redirects.txt

The second line contains the original URL. The third line contains the new URL. For example:

```
Audion
http://freedb.freedb.org/
https:/gnudb.gnudb.org/
```

This rule means "send any traffic Audion addressed to freedb.freedb.org to gnudb.gnudb.org instead".

### headers.txt

The second line contains a URL. Every subsequent line contains a custom header to apply to the URL. To unset an existing header, don't put anything after the colon. For example:

```
SoundJam
http://dogcow.com/moof.php
X-API-Key: abcdefgh1234567
User-Agent: OmniWeb/3.0.2
Accept-Encoding:
```

### flags.txt

Each line names one optional behavior to turn on. Two are recognized:

```
debug
disabled-mtls
```

- debug — log each secure connection to /tmp/aquatransport-<your-user-id>.log.
- disabled-mtls — for apps that sign in with a client certificate. These normally work through AquaTransport; turn this on to hand them back to the system, the way they worked before, if one of them doesn't.