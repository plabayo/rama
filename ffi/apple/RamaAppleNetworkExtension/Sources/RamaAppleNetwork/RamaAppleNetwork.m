#import "RamaAppleNetwork.h"

#if !__has_feature(objc_arc)
#error This adapter requires ARC for the asynchronous buffer lifetimes.
#endif

nw_parameters_t rama_nw_tcp_parameters(void) {
    return nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                           NW_PARAMETERS_DEFAULT_CONFIGURATION);
}

void rama_nw_tcp_send(nw_connection_t connection, NSData *data, bool final, bool complete,
                      void (^completion)(nw_error_t)) {
    // Keep the immutable NSData alive for the lifetime of dispatch_data's bytes.
    // There is no additional payload copy at this boundary.
    dispatch_data_t content = data ? dispatch_data_create(data.bytes, data.length, NULL,
                                                          ^{
                                                            (void)data;
                                                          })
                                   : NULL;
    nw_connection_send(connection, content,
                       final ? NW_CONNECTION_FINAL_MESSAGE_CONTEXT
                             : NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
                       complete, completion ?: NW_CONNECTION_SEND_IDEMPOTENT_CONTENT);
}

void rama_nw_tcp_receive(nw_connection_t connection, uint32_t minimum, uint32_t maximum,
                         void (^completion)(NSData *, bool, nw_error_t)) {
    nw_connection_receive(
        connection, minimum, maximum,
        ^(dispatch_data_t content, nw_content_context_t context, bool complete, nw_error_t error) {
          NSData *data = nil;
          if (content) {
              const void *bytes = NULL;
              size_t count = 0;
              dispatch_data_t mapped = dispatch_data_create_map(content, &bytes, &count);
              if (mapped) {
                  data = [[NSData alloc] initWithBytesNoCopy:(void *)bytes
                                                      length:count
                                                 deallocator:^(void *buffer, NSUInteger length) {
                                                   (void)mapped;
                                                 }];
              }
          }
          completion(data, complete, error);
        });
}
