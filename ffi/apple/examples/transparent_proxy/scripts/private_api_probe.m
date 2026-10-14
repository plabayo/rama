// Availability/call smoke test only: no connection, attribution or PAC behavior.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <TargetConditionals.h>
#include <dlfcn.h>

#ifndef RAMA_PROBE_SYMBOL
#define RAMA_PROBE_SYMBOL "nw_parameters_set_no_proxy"
#endif

#ifdef RAMA_PROBE_LINK_ONLY
extern void nw_parameters_set_no_proxy(nw_parameters_t parameters, bool value);
#endif

int main(void) {
    @autoreleasepool {
#ifdef RAMA_PROBE_LINK_ONLY
        void (*setter)(nw_parameters_t, bool) = nw_parameters_set_no_proxy;
#else
        void (*setter)(nw_parameters_t, bool) = dlsym(RTLD_DEFAULT, RAMA_PROBE_SYMBOL);
#endif
        if (setter == NULL) {
            fprintf(stderr, "Missing private symbol: %s\n", RAMA_PROBE_SYMBOL);
            return 1;
        }
        nw_parameters_t parameters = nw_parameters_create_secure_tcp(
            NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        if (parameters == NULL) return 2;
        setter(parameters, true);
        setter(parameters, false);
        NSDictionary *report = @{
            @"symbol": @RAMA_PROBE_SYMBOL,
            @"platform": TARGET_OS_SIMULATOR ? @"ios-simulator" : @"macos",
            @"os": NSProcessInfo.processInfo.operatingSystemVersionString,
            @"called_true_and_false": @YES
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:0 error:nil];
        if (json == nil) return 3;
        puts([[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String);
    }
    return 0;
}
