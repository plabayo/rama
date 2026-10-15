#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

// Public C API constants and dispatch_data bridging not exposed by Swift's overlay.
nw_parameters_t rama_nw_tcp_parameters(void);
void rama_nw_tcp_send(nw_connection_t connection, NSData *_Nullable data, bool final, bool complete,
                      void (^_Nullable completion)(nw_error_t _Nullable));
void rama_nw_tcp_receive(nw_connection_t connection, uint32_t minimum, uint32_t maximum,
                         void (^completion)(NSData *_Nullable, bool, nw_error_t _Nullable));

NS_ASSUME_NONNULL_END
