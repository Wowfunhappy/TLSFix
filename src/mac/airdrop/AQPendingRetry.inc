/* A receiver can remain pending after Finder closes its AirDrop browser.
 * Retrying that receiver alone would repeatedly take Wi-Fi into monitor mode
 * even though nobody is browsing. */
static void retry_pending_radio(BOOL bluetooth_on) {
    if(native_mode || !bluetooth_on || !active_browsers.count ||
       (!pending_browsers.count && !pending_servers.count)) return;
    for(id server in [pending_servers allObjects]) start_server(server,@selector(startHTTPServer));
    for(id browser in [pending_browsers allObjects]) start_browser(browser,@selector(start));
}
