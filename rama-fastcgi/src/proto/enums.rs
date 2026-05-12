use rama_utils::macros::enums::enum_builder;

enum_builder! {
    /// Type of a FastCGI record.
    ///
    /// Distinguishes between management records (requestId == 0) and
    /// application records (requestId != 0).
    ///
    /// Reference: FastCGI spec §8
    @U8
    pub enum RecordType {
        /// Sent by the web server to begin a new request.
        ///
        /// Reference: FastCGI Specification §5.1
        BeginRequest => 1,
        /// Sent by the web server to abort a request.
        ///
        /// Reference: FastCGI Specification §5.4
        AbortRequest => 2,
        /// Sent by the application to terminate a request.
        ///
        /// Reference: FastCGI Specification §5.5
        EndRequest => 3,
        /// Carries CGI/environment name-value pairs from web server to application (stream).
        ///
        /// An empty PARAMS record (contentLength == 0) terminates the stream.
        ///
        /// Reference: FastCGI Specification §5.2
        Params => 4,
        /// Carries the request body from web server to application (stream).
        ///
        /// An empty STDIN record (contentLength == 0) terminates the stream.
        ///
        /// Reference: FastCGI Specification §5.3
        Stdin => 5,
        /// Carries the application's response from application to web server (stream).
        ///
        /// An empty STDOUT record (contentLength == 0) terminates the stream.
        ///
        /// Reference: FastCGI Specification §5.3
        Stdout => 6,
        /// Carries error output from application to web server (stream).
        ///
        /// An empty STDERR record (contentLength == 0) terminates the stream.
        ///
        /// Reference: FastCGI Specification §5.3
        Stderr => 7,
        /// Carries extra data from web server to application (filter role only, stream).
        ///
        /// An empty DATA record (contentLength == 0) terminates the stream.
        ///
        /// Reference: FastCGI Specification §5.3
        Data => 8,
        /// Management record: query application for specific variables.
        ///
        /// requestId must be 0 (FCGI_NULL_REQUEST_ID).
        ///
        /// Reference: FastCGI Specification §4.1
        GetValues => 9,
        /// Management record: response to a GET_VALUES query.
        ///
        /// requestId must be 0 (FCGI_NULL_REQUEST_ID).
        ///
        /// Reference: FastCGI Specification §4.1
        GetValuesResult => 10,
        /// Management record: response to an unrecognised management record type.
        ///
        /// requestId must be 0 (FCGI_NULL_REQUEST_ID).
        ///
        /// Reference: FastCGI Specification §4.2
        UnknownType => 11,
    }
}

enum_builder! {
    /// Role of the FastCGI application in a request.
    ///
    /// Sent in the [`BeginRequestBody`] to indicate how the application is expected to behave.
    ///
    /// Reference: FastCGI spec §6
    ///
    /// [`BeginRequestBody`]: crate::proto::BeginRequestBody
    @U16
    pub enum Role {
        /// The application generates a response for every request.
        ///
        /// This is the most common role and equivalent to a traditional CGI program.
        ///
        /// Reference: FastCGI Specification §6.2
        Responder => 1,
        /// The application authorises or denies a request before the web server handles it.
        ///
        /// Reference: FastCGI Specification §6.3
        Authorizer => 2,
        /// The application processes data associated with a file, and the web server
        /// provides both the file data and extra stream data.
        ///
        /// Reference: FastCGI Specification §6.4
        Filter => 3,
    }
}

enum_builder! {
    /// Protocol-level status of a completed request, carried in [`EndRequestBody`].
    ///
    /// Reference: FastCGI spec §5.5
    ///
    /// [`EndRequestBody`]: crate::proto::EndRequestBody
    @U8
    pub enum ProtocolStatus {
        /// The request completed normally.
        ///
        /// > The application processed the request normally, and the
        /// > `appStatus` carries the application-level exit status.
        ///
        /// Reference: FastCGI Specification §5.5
        RequestComplete => 0,
        /// This application cannot handle concurrent requests over a single connection.
        ///
        /// The web server should open a new connection for the request.
        ///
        /// Reference: FastCGI Specification §5.5
        CantMpxConn => 1,
        /// The application is temporarily overloaded.
        ///
        /// The web server should retry the request later.
        ///
        /// Reference: FastCGI Specification §5.5
        Overloaded => 2,
        /// The role value in the `FCGI_BEGIN_REQUEST` record was not recognised.
        ///
        /// Reference: FastCGI Specification §5.5
        UnknownRole => 3,
    }
}
