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

Each line names one optional behavior to turn on:

```
debug
disabled-mtls
allow-legacy-tls
```

- debug — log each secure connection to the system log (Console.app, or `syslog -k Sender <app>`). Look for lines tagged AquaTransport.
- disabled-mtls — for apps that sign in with a client certificate. These normally work through AquaTransport; turn this on to hand them back to the system, the way they worked before, if one of them doesn't.
- allow-legacy-tls — AquaTransport normally refuses the old, broken parts of TLS: versions 1.0 and 1.1, and cipher suites like 3DES and RC4. It also keeps that refusal final, rather than letting your Mac's own older software quietly complete the connection instead. Turn this on if some site or device on your network still needs the old way — it lifts both at once, because allowing one without the other would reach the server anyway and just not tell you. It applies from the next connection, with no restart.

Changes to these take effect straight away, on the next connection.

There is also a set of `gate-` flags that control the background daemon, which is what gets AquaTransport into an app before that app's first connection. The only one worth knowing about is `gate-off`, which turns that off — apps then get AquaTransport shortly after they launch instead of exactly when they need it, so a request made in the first moments of an app's life can slip through unfixed. It is there in case the daemon ever causes trouble. These are read when the daemon starts, so run:

```
sudo launchctl unload /Library/LaunchDaemons/org.aquatransport.watch.plist
sudo launchctl load /Library/LaunchDaemons/org.aquatransport.watch.plist
```

after changing one. The rest are documented in docs/TECHNICAL.md.