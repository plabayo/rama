# ICAP Errata

---

a comprehensive collection of RFC 3507 bugs

This page collects [RFC 3507](http://www.ietf.org/rfc/rfc3507.txt) errata and is meant to reflect all known issues. New errata entries can be posted to the [ICAP Forum](http://www.i-cap.org)'s subscribers-only mailing [list](http://groups.yahoo.com/group/icap-discussions/) or emailed directly to the [maintainer](mailto:rousskov@measurement-factory.org?subject=ICAP errata).

All errata entries has been reviewed by ICAP Forum folks. The first eight entries were sent to and did not cause objections from RFC 3507 authors. This page is a part of the official errata [database](http://www.rfc-editor.org/errata.html) of RFCs.

You can browse errata entries below, view the [revised text](https://www.measurement-factory.com/std/icap/rfc3507-fixed.txt) with all known bugs fixed, or see the [diffs](https://www.measurement-factory.com/std/icap/rfc3507-diffs.html) generated against the [original RFC 3507](http://www.ietf.org/rfc/rfc3507.txt).

## Index of errata entries

- When to send an Encapsulated header
- Encapsulated HTTP trailers must be supported
- ICAP trailers require negotiation
- Encapsulated HTTP headers are optional
- Rejecting encapsulated sections
- Safe on-the-fly chunking implementation
- Early ICAP responses
- OPTIONS example missing CRLF
- Preview example missing CRLF

## When to send an Encapsulated header

Entry ID: e1
First posted: 2004/04/07
Updates: [2004/11/04](http://groups.yahoo.com/group/ICAP-Discussions/message/276) , [2004/11/11](http://groups.yahoo.com/group/ICAP-Discussions/message/279)
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/217) [[1]](http://groups.yahoo.com/group/ICAP-Discussions/message/221) [[2]](http://groups.yahoo.com/group/ICAP-Discussions/message/228) [[3]](http://groups.yahoo.com/group/ICAP-Discussions/message/278)
Credits: [Jeffrey Merrick](mailto:jeffrey_merrick_shouldnotbespammed@host_yahoo.com) , [Martin Stecher](mailto:martin.stecher_shouldnotbespammed@host_webwasher.com) , [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com) , [Manik Taneja](mailto:aiwiu_shouldnotbespammed@host_yahoo.com)

Several RFC 3507 MUST-level requirements prescribe inclusion of Encapsulated header in every ICAP message. However, RFC 3507 does not show Encapsulated header in OPTIONS requests. Implementations usually do not include Encapsulated header with "100 Continue" and "204 No Content" responses. Moreover, some popular implementations cannot handle Encapsulated header presence in those messages and possibly other messages that usually lack body.

To make the specification consistent, the presence of an ICAP message-body is now determined by the presence and value of an Encapsulated header. This is a syntax-level rule: no header means no body and no further analysis is needed. To improve interoperation, bodies are explicitly prohibited (or required) in certain cases where older implementations may not be able to handle the message otherwise.

**Old page 11, line 28:**

**Before:**

```text
   message format of RFC 2822 [3] -- that is, a start-line (either a
   request line or a status line), a number of header fields (also known
   as "headers"), an empty line (i.e., a line with nothing preceding the
   CRLF) indicating the end of the header fields, and a message-body.

   The header lines of an ICAP message specify the ICAP resource being
   requested as well as other meta-data such as cache control
```

**New page 11, line 28:**

**After:**

```text
   message format of RFC 2822 [3] -- that is, a start-line (either a
   request line or a status line), a number of header fields (also known
   as "headers"), an empty line (i.e., a line with nothing preceding the
   CRLF) indicating the end of the header fields, and possibly a
   message-body.

   The presence of a message-body is determined exclusively by the
   presence and value of the Encapsulated header documented in Section
   4.4. Thus, the sender MUST include the Encapsulated header in every
   ICAP message with message-body. The message-body syntax and semantics
   are determined by the value of the Encapsulated header.

   The header lines of an ICAP message specify the ICAP resource being
   requested as well as other meta-data such as cache control
```

**Old page 16, line 29:**

**Before:**

```text
   The offset of each encapsulated section's start relative to the start
   of the encapsulating message's body is noted using the "Encapsulated"
   header.  This header MUST be included in every ICAP message.  For
   example, the header

      Encapsulated: req-hdr=0, res-hdr=45, res-body=100
```

**New page 16, line 29:**

**After:**

```text
   The offset of each encapsulated section's start relative to the start
   of the encapsulating message's body is noted using the "Encapsulated"
   header. For example, the header

      Encapsulated: req-hdr=0, res-hdr=45, res-body=100
```

**Old page 16, line 40:**

**Before:**

```text
   decimal notation for consistency with HTTP's Content-Length header.

   The special entity "null-body" indicates there is no encapsulated
   body in the ICAP message.

   The syntax of an Encapsulated header is:
```

**New page 16, line 39:**

**After:**

```text
   decimal notation for consistency with HTTP's Content-Length header.

   The special entity "null-body" indicates there is no encapsulated
   HTTP body in the ICAP message. An Encapsulated header value of
   "null-body=0" describes a message-body of zero length, which is
   syntactically equivalent to having no message-body. A value of
   "null-body=0" is common for OPTIONS responses, for example.

   The syntax of an Encapsulated header is:
```

**Old page 17, line 9:**

**Before:**

```text
   appear in the encapsulating message-body MUST be the same as the
   order in which the parts are named in the Encapsulated header.  In
   other words, the offsets listed in the Encapsulated line MUST be
   monotonically increasing.  In addition, the legal forms of the
   Encapsulated header depend on the method being used (REQMOD, RESPMOD,
   or OPTIONS).  Specifically:

   REQMOD  request  encapsulated_list: [reqhdr] reqbody
   REQMOD  response encapsulated_list: {[reqhdr] reqbody} |
                                       {[reshdr] resbody}
   RESPMOD request  encapsulated_list: [reqhdr] [reshdr] resbody
   RESPMOD response encapsulated_list: [reshdr] resbody
   OPTIONS response encapsulated_list: optbody

   In the above grammar, note that encapsulated headers are always
   optional.  At most one body per encapsulated message is allowed.  If
   no encapsulated body is presented, the "null-body" header is used
   instead; this is useful because it indicates the length of the header
   section.

   Examples of legal Encapsulated headers:

   /* REQMOD request: This encapsulated HTTP request's headers start
```

**New page 17, line 9:**

**After:**

```text
   appear in the encapsulating message-body MUST be the same as the
   order in which the parts are named in the Encapsulated header.  In
   other words, the offsets listed in the Encapsulated line MUST be
   monotonically increasing.

   In addition, the legal forms of the Encapsulated header value depend
   on the request method. The value MUST use the following grammar for
   matching requests and 200 "OK" responses to those requests.

   REQMOD  request  encapsulated_list: [reqhdr] reqbody
   REQMOD  response encapsulated_list: {[reqhdr] reqbody} |
                                       {[reshdr] resbody}
   RESPMOD request  encapsulated_list: [reqhdr] [reshdr] resbody
   RESPMOD response encapsulated_list: [reshdr] resbody
   OPTIONS request  encapsulated_list: [optbody]
   OPTIONS response encapsulated_list: optbody

   In the above grammar, note that encapsulated headers are always
   optional.  At most one encapsulated body per ICAP message is allowed.
   If no encapsulated body is presented, the "null-body" header is used
   instead; this is useful because it indicates the length of the header
   section.

   Interpretation of a message-body depends on the Encapsulated header
   value.  This specification defines Encapsulated value semantics for
   three request methods and 200 "OK" responses to those requests. The
   sender MUST NOT include a message-body in any other message unless it
   knows the recipient can handle it; the mechanism to obtain such
   knowledge is beyond the scope of this document. For example, requests
   using extension methods and responses other than 200 "OK" must not
   include a message-body unless the recipient knows how to interpret
   it.

   Examples of legal Encapsulated headers:

   /* REQMOD request: This encapsulated HTTP request's headers start
```

**Old page 20, line 49:**

**Before:**

```text
      symbol explained below), then the ICAP server MUST NOT respond
      with 100 Continue.

   When an ICAP client is performing a preview, it may not yet know how
   many bytes will ultimately be available in the arriving HTTP message
   that it is relaying to the HTTP server.  Therefore, ICAP defines a
```

**New page 20, line 49:**

**After:**

```text
      symbol explained below), then the ICAP server MUST NOT respond
      with 100 Continue.

   As prescribed in Section 4.1.1, 100 "Continue" and 204 "No Content"
   responses must not have message-bodies by default.

   When an ICAP client is performing a preview, it may not yet know how
   many bytes will ultimately be available in the arriving HTTP message
   that it is relaying to the HTTP server.  Therefore, ICAP defines a
```

**Old page 30, line 8:**

**Before:**

```text
   Other headers are also allowed as described in Section 4.3.1 and
   Section 4.3.2 (for example, Host).

4.10.2 OPTIONS Response

   The OPTIONS response consists of a status line as described in
```

**New page 30, line 8:**

**After:**

```text
   Other headers are also allowed as described in Section 4.3.1 and
   Section 4.3.2 (for example, Host).

   Some ICAP servers may not be able to handle OPTIONS requests with
   message-body because earlier protocol specifications did not
   explicitly allow or prohibit such requests.  An ICAP client MUST NOT
   send an OPTIONS request with a message-body, unless the client knows
   that the server can handle such a request.

4.10.2 OPTIONS Response

   The OPTIONS response consists of a status line as described in
```

## Encapsulated HTTP trailers must be supported

Entry ID: e2
First posted: 2004/03/10
Last updated: 2004/11/01
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/207) [[1]](http://groups.yahoo.com/group/ICAP-Discussions/message/208)
Credits: [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com) , [Martin Stecher](mailto:martin.stecher_shouldnotbespammed@host_webwasher.com)

HTTP chunked encoding allows an agent to send some HTTP headers after the last-chunk, in an encoding area called "trailer". Since ICAP is using HTTP chunked encoding, ICAP messages with encapsulated bodies may contain HTTP trailers. However, many implementations overlook such possibility and strip, ignore, or otherwise incorrectly handle HTTP trailers they receive.

To preserve HTTP message integrity, HTTP trailers must be treated the same way other parts of HTTP content is treated. For example, an ICAP server that does not intend to modify the encapsulated message must send all received HTTP trailers (if any) back to the ICAP client.

**Old page 16, line 25:**

**Before:**

```text
   (See Examples in Sections 4.8.3 and 4.9.3.).  The motivation behind
   this decision is described in Section 8.2.

4.4.1  The "Encapsulated" Header

   The offset of each encapsulated section's start relative to the start
```

**New page 16, line 25:**

**After:**

```text
   (See Examples in Sections 4.8.3 and 4.9.3.).  The motivation behind
   this decision is described in Section 8.2.

   HTTP chunked transfer-coding may include a trailer area containing
   HTTP entity-header fields. Since ICAP requires support for chunked
   transfer-coding, an ICAP agent MUST accept an encapsulated trailer,
   if any (i.e., the presence of a trailer must not prevent ICAP
   recipient from correctly parsing and handling an ICAP message).
   Similar to other HTTP message parts, an ICAP server MUST send the
   received trailer back to the ICAP client unless the ICAP server
   modifies or strips trailers as a part of server content adaptation
   actions.

4.4.1  The "Encapsulated" Header

   The offset of each encapsulated section's start relative to the start
```

## ICAP trailers require negotiation

Entry ID: e3
First posted: 2004/03/10
Last updated: 2004/11/01
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/207) [[1]](http://groups.yahoo.com/group/ICAP-Discussions/message/208) [[2]](http://groups.yahoo.com/group/ICAP-Discussions/message/211)
Credits: [Jeffrey Merrick](mailto:jeffrey_merrick_shouldnotbespammed@host_yahoo.com) , [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com) , [Martin Stecher](mailto:martin.stecher_shouldnotbespammed@host_webwasher.com)

HTTP chunked encoding allows an agent to send some HTTP headers after the last-chunk, in an encoding area called "trailer". Since ICAP is using HTTP chunked encoding, it may be tempting to put some ICAP headers after the encapsulated HTTP body. However, encapsulated HTTP message may also contain trailers. In general, trailer recipient cannot distinguish between ICAP and HTTP headers in the trailer.

To preserve HTTP message integrity, ICAP trailers must not be sent unless the sender knows that the recipient will not confuse them with HTTP trailers.

**Old page 16, line 25:**

**Before:**

```text
   (See Examples in Sections 4.8.3 and 4.9.3.).  The motivation behind
   this decision is described in Section 8.2.

4.4.1  The "Encapsulated" Header

   The offset of each encapsulated section's start relative to the start
```

**New page 16, line 25:**

**After:**

```text
   (See Examples in Sections 4.8.3 and 4.9.3.).  The motivation behind
   this decision is described in Section 8.2.

   An ICAP agent MUST NOT send an ICAP header in a trailer area of the
   ICAP message-body encoding unless it knows the recipient expects such
   a header. This document does not define how such an expectation is
   negotiated. In general, sending ICAP headers in the trailer makes it
   impossible for the trailer recipient to distinguish HTTP headers from
   ICAP headers.

4.4.1  The "Encapsulated" Header

   The offset of each encapsulated section's start relative to the start
```

## Encapsulated HTTP headers are optional

Entry ID: e4
First posted: 2004/05/27
Last updated: 2004/11/01
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/235)
Credits: [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com)

Section 4.4.1 'The "Encapsulated" Header' of RFC 3507 says: "note that encapsulated headers are always optional". On the other hand, Section 4.8.1 dealing with REQMOD request says: "In REQMOD mode, [...] The headers and body (if any) MUST both be encapsulated". Moreover, Section 4.9.1 dealing with RESPMOD request says: "Using encapsulation described in Section 4.4, the header and body of the HTTP response to be modified MUST be included in the ICAP body".

A simple and consistent policy would be to send only those parts that the receiving ICAP agent might need. If desired, HTTP message headers (or body) can be omitted.

**Old page 17, line 21:**

**Before:**

```text
   OPTIONS response encapsulated_list: optbody

   In the above grammar, note that encapsulated headers are always
   optional.  At most one body per encapsulated message is allowed.  If
   no encapsulated body is presented, the "null-body" header is used
   instead; this is useful because it indicates the length of the header
   section.
```

**New page 17, line 21:**

**After:**

```text
   OPTIONS response encapsulated_list: optbody

   In the above grammar, note that encapsulated headers are always
   OPTIONAL.  At most one body per encapsulated message is allowed.  If
   no encapsulated body is presented, the "null-body" header is used
   instead; this is useful because it indicates the length of the header
   section.
```

**Old page 23, line 45:**

**Before:**

```text
4.8.1  Request

   In REQMOD mode, the ICAP request MUST contain an encapsulated HTTP
   request.  The headers and body (if any) MUST both be encapsulated,
   except that hop-by-hop headers are not encapsulated.

4.8.2  Response
```

**New page 23, line 45:**

**After:**

```text
4.8.1  Request

   In REQMOD mode, the ICAP request contains an encapsulated HTTP
   request.  An HTTP request has at most two parts: HTTP request headers
   (including HTTP Request-Line) and possibly an HTTP request body.  An
   ICAP client MUST encapsulate at least one part. If the request body
   is not encapsulated, the client MUST use the "null-body" entity.

   To improve interoperability, an ICAP client SHOULD encapsulate all
   available HTTP request parts unless it knows the ICAP server expects
   just one part.  Note that an HTTP trailer, if any, is a part of the
   chunked HTTP request body and, hence, may be present in an ICAP
   REQMOD request even if HTTP request headers are not encapsulated.

   An ICAP client MUST NOT encapsulate HTTP hop-by-hop request headers.

4.8.2  Response
```

**Old page 27, line 38:**

**Before:**

```text
4.9.1  Request

   Using encapsulation described in Section 4.4, the header and body of
   the HTTP response to be modified MUST be included in the ICAP body.
   If available, the header of the original client request SHOULD also
   be included.  As with the other method, the hop-by-hop headers of the
   encapsulated messages MUST NOT be forwarded.  The Encapsulated header
   MUST indicate the byte-offsets of the beginning of each of these four
   parts.

4.9.2  Response
```

**New page 27, line 38:**

**After:**

```text
4.9.1  Request

   In RESPMOD mode, the ICAP request contains optional encapsulated HTTP
   request headers and an encapsulated HTTP response. An HTTP response
   has at most two parts: HTTP response headers (including HTTP
   Status-Line) and possibly an HTTP response body.  An ICAP client MUST
   encapsulate at least one of those two parts. If the HTTP response
   body is not encapsulated, the client MUST use the "null-body" entity.

   To improve interoperability, an ICAP client SHOULD encapsulate HTTP
   request headers and all available HTTP response parts unless it knows
   the ICAP server expects something else.  Note that an HTTP trailer,
   if any, is a part of the chunked HTTP response body and, hence, may
   be present in an ICAP RESPMOD request even if HTTP response headers
   are not encapsulated.

   An ICAP client MUST NOT encapsulate HTTP hop-by-hop response headers.

4.9.2  Response
```

## Rejecting encapsulated sections

Entry ID: e5
First posted: 2004/05/28
Last updated: 2004/11/01
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/236) [[1]](http://groups.yahoo.com/group/ICAP-Discussions/message/242)
Credits: [Martin Stecher](mailto:martin.stecher_shouldnotbespammed@host_webwasher.com)

ICAP clients may not encapsulate all HTTP message parts expected by ICAP servers or may encapsulated parts that an ICAP server cannot handle. In either case there needs to be a way for an ICAP server to report a request composition mismatch, even though the ICAP request was syntactically valid. RFC 3507 lacks an appropriate error code.

ICAP extensions may document how ICAP agents can negotiate what message parts need to be encapsulated. Such negotiations are outside of the RFC 3507 scope.

**Old page 14, line 50:**

**Before:**

```text
   408 - Request timeout.  ICAP server gave up waiting for a request
         from an ICAP client.

   500 - Server error.  Error on the ICAP server, such as "out of disk
         space".
```

**New page 14, line 50:**

**After:**

```text
   408 - Request timeout.  ICAP server gave up waiting for a request
         from an ICAP client.

   418 - Bad composition.  ICAP server needs encapsulated sections
         different from those in the request.

   500 - Server error.  Error on the ICAP server, such as "out of disk
         space".
```

**Old page 17, line 26:**

**Before:**

```text
   instead; this is useful because it indicates the length of the header
   section.

   Examples of legal Encapsulated headers:

   /* REQMOD request: This encapsulated HTTP request's headers start
```

**New page 17, line 26:**

**After:**

```text
   instead; this is useful because it indicates the length of the header
   section.

   An ICAP server receiving encapsulated_list that does not match server
   needs MAY respond with a 418 "Bad Composition" error. This situation
   may happen, for example, when the server does not receive
   encapsulated HTTP requests headers in a RESPMOD request but needs
   them to process the encapsulated HTTP response.

   Examples of legal Encapsulated headers:

   /* REQMOD request: This encapsulated HTTP request's headers start
```

## Safe on-the-fly chunking implementation

Entry ID: e6
First posted: 2004/09/20
Updates: 2004/11/01 , [2004/11/24](http://groups.yahoo.com/group/ICAP-Discussions/message/296)
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/266)
Credits: [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com) , [Manik Taneja](mailto:aiwiu_shouldnotbespammed@host_yahoo.com)

The "Implementation Notes" section of RFC 3507 gives incorrect recommendation regarding chunking of incoming HTTP messages. The notes imply that chunk sizes can be sent to the ICAP server before a the corresponding chunk content is received by the ICAP client. Doing so would require closing ICAP connection if less-than-expected data is received. Closing an ICAP connection before completing the request may disable essential ICAP filters or block functioning web sites that, for example, send wrong Content-Length header due to an origin server or CGI program bug.

Instead, the implementations should chunk and send only available data and not "promise" more data when sizing chunks. Chunking and sending whatever content is available in receive buffers would work. As an optimization, an implementation may wait some time for "enough data" or perhaps "complete HTTP chunk" to be available when converting HTTP chunks to ICAP chunks.

**Old page 37, line 11:**

**Before:**

```text
   encoding within the encapsulated body section as defined in HTTP/1.1
   [4].  This requires that ICAP client implementations convert incoming
   objects "on the fly" to chunked from whatever transfer-encoding on
   which they arrive.  However, the transformation is simple:

   -  For objects arriving using "Content-Length" headers, one big chunk
      can be created of the same size as indicated in the Content-Length
      header.

   -  For objects arriving using a TCP close to signal the end of the
      object, each incoming group of bytes read from the OS can be
      converted into a chunk (by writing the length of the bytes read,
      followed by the bytes themselves)

   -  For objects arriving using chunked encoding, they can be
      retransmitted as is (without re-chunking).

6.4  Distinct URIs for Distinct Services
```

**New page 37, line 11:**

**After:**

```text
   encoding within the encapsulated body section as defined in HTTP/1.1
   [4].  This requires that ICAP client implementations convert incoming
   objects "on the fly" to chunked from whatever transfer-encoding on
   which they arrive.  A straightforward conversion approach is
   highlighted below.

   As object content comes in, the ICAP client converts all available
   content bytes into a single chunk to be sent to the ICAP server.  If
   incoming content is chunked-encoded, the client decodes the encoding
   first, to get access to object content. The client follows HTTP rules
   to detect the end of the incoming HTTP message. For example, if the
   client gets an HTTP message with Content-Length of 100KB and gets the
   first 100 bytes of that message content, the client can send the
   first 100 bytes as a single complete chunk. The client should neither
   (a) wait a long time for all 100KB to arrive or (b) announce a 100KB
   chunk but send the first 100 bytes only.

   The above straightforward process can be optimized to minimize
   copying of content bytes, even if the incoming content is chunked.
   For example, an implementation can wait a little for more HTTP
   content (or the entire HTTP chunk) to become available before forming
   and sending a chunk to the ICAP server.

   When object content length is known a priori, it is tempting to
   declare a single chunk of matching size and then forward incoming
   object data as it comes in, without any additional encoding efforts.
   Similarly, it is tempting to forward already chunked content "as is",
   without re-chunking it first.

   However, unrecoverable errors may occur when an ICAP client promises
   to send chunk content that it does not yet have because the promised
   data may never arrive due to origin server or network errors.
   Chunked coding does not have a mechanism to terminate a chunk
   prematurely; the ICAP server would expect all promised bytes.  Thus,
   if ICAP client receives fewer than expected HTTP bytes, it has no
   other choice but to close the ICAP connection. A straightforward
   approach described above does not make false promises and avoids the
   problem.

6.4  Distinct URIs for Distinct Services
```

## Early ICAP responses

Entry ID: e7
First posted: 2004/07/15
Updates: 2004/11/01 , [2005/06/01](http://groups.yahoo.com/group/ICAP-Discussions/message/345)
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/243) [[1]](http://groups.yahoo.com/group/ICAP-Discussions/message/247) [[2]](http://groups.yahoo.com/group/ICAP-Discussions/message/254) [[3]](http://groups.yahoo.com/group/ICAP-Discussions/message/257) [[4]](http://groups.yahoo.com/group/ICAP-Discussions/message/297)
Credits: [Martin Stecher](mailto:martin.stecher_shouldnotbespammed@host_webwasher.com) , [Sean Gwizdak](mailto:sgwizdak_shouldnotbespammed@host_gmail.com) , [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com)

Some ICAP servers start sending an 200 "OK" response "early", before they receive a complete ICAP request. ICAP servers do this in order to reduce HTTP transaction latency. RFC 3507 does not allow or prohibit this behavior and only vaguely encourages "incremental" responses, without defining what they are and when they can start.

Early responses break interoperability when an ICAP client does not start reading the response until it is done sending the request, resulting in a TCP deadlock: (a) neither the client nor the server can send more data, (b) the server cannot read more data, and (c) the client would not read more data.

Similar problem exists with early 204 "No Content" responses. RFC 3507 neither allows nor forbids 204 responses to be sent before the end of the initial ICAP request message.

While RFC 3507 does not explicitly define error timing and handling, it is reasonable to adopt HTTP practice of monitoring connections for early error responses. Not doing so may lead to deadlocks as well.

Since clients have to monitor for early errors, they have to monitor for any early response because the response status is unknown a priori. Most clients probably already read and "pipeline" early 200 responses due to obvious benefits to the end-user. Not reading an early 200 response would also place a limit on ICAP-able content size because an ICAP server may not be able to store huge responses. Finally, a 200 response may end before the client finished sending the corresponding request. Thus, ICAP clients that read early responses, must already handle 204-like conditions when the response is completed before the request.

Given all of the factors, ICAP clients should be required to handle all early responses. In the absence of explicit negotiation (not defined here), the client has to complete the request even though it has received an early response.

An ICAP extension (not defined here) can allow clients to disclaim support for early responses. When such an extension is enabled, the server unable to buffer the entire incoming encapsulated message would have to discard the incoming data and respond with an error once it receives a complete ICAP request.

**Old page 11, line 42:**

**Before:**

```text
   allowing only one outstanding request on a transport connection at a
   time.  Multiple parallel connections MAY be used as in HTTP.

4.2  ICAP URIs

   All ICAP requests specify the ICAP resource being requested from the
```

**New page 11, line 42:**

**After:**

```text
   allowing only one outstanding request on a transport connection at a
   time.  Multiple parallel connections MAY be used as in HTTP.

   An ICAP client sending a message-body MUST monitor the transport
   connection for an early ICAP response (i.e., the response that comes
   while the client is still transmitting the request). Such a response
   may be a successful (e.g., 200 "OK") response or not (e.g., 400 "Bad
   Request"). Just like HTTP rules in Section 8.2.2 of [4], this
   requirement eliminates a deadlock when neither client nor server can
   send more data. However, correct early response handling is more
   important (and not limited to errors) for ICAP because ICAP servers
   often have to respond early to avoid buffering the entire
   encapsulated message. Early responses may also decrease end-user
   perceived latency if the client pipelines received content to the
   end-user.

   Regardless of the early response meaning and timing, the ICAP client
   SHOULD finish sending the request. If the client chooses not to
   finish the request, it MUST terminate the transport connection after
   receiving the early response because the ICAP server would not be
   able to detect the end of the ICAP request otherwise.  ICAP
   extensions (not defined in this document) MAY supersede these
   requirements by documenting ways to abort the request without
   terminating the transport connection abnormally.

4.2  ICAP URIs

   All ICAP requests specify the ICAP resource being requested from the
```

## OPTIONS example missing CRLF

Entry ID: e8
First posted: 2004/10/31
Last updated: 2004/11/01
References: 
Credits: [Alex Rousskov](mailto:rousskov_shouldnotbespammed@host_measurement-factory.com)

A new line is missing in one of the OPTIONS request examples.

**Old page 29, line 49:**

**Before:**

```text
   The OPTIONS method consists of a request-line, as described in
   Section 4.3.2, such as the following example:

   OPTIONS icap://icap.server.net/sample-service ICAP/1.0 User-Agent:
   ICAP-client-XYZ/1.001

   Other headers are also allowed as described in Section 4.3.1 and
   Section 4.3.2 (for example, Host).
```

**New page 29, line 49:**

**After:**

```text
   The OPTIONS method consists of a request-line, as described in
   Section 4.3.2, such as the following example:

   OPTIONS icap://icap.server.net/sample-service ICAP/1.0
   User-Agent: ICAP-client-XYZ/1.001

   Other headers are also allowed as described in Section 4.3.1 and
   Section 4.3.2 (for example, Host).
```

## Preview example missing CRLF

Entry ID: e9
First posted: 2010/04/17
References: [[0]](http://groups.yahoo.com/group/ICAP-Discussions/message/585)
Credits: [Run Out](mailto:runout_shouldnotbespammed@host_rocketmail.com)

A new line is missing after last-chunk in one of the Preview request examples.

**Old page 22, line 9:**

**Before:**

```text
      <512 bytes of data>\r\n
      200\r\n
      <512 bytes of data>\r\n
      0\r\n

      <100 Continue Message>
```

**New page 22, line 9:**

**After:**

```text
      <512 bytes of data>\r\n
      200\r\n
      <512 bytes of data>\r\n
      0\r\n\r\n

      <100 Continue Message>
```

---

## Acknowledgments

Creation and maintenance of this page is sponsored by the [Measurement Factory](http://www.measurement-factory.com/).

The original idea of a colored before/after diff and its color scheme come from the "HTTP/1.1 Specification Errata" [page](http://purl.org/NET/http-errata) maintained by [Scott Lawrence](mailto:%73%63%6F%74%74%2D%68%74%74%70%40%73%6B%72%62%2E%6F%72%67).

Diffs are generated with a [modified](https://www.measurement-factory.com/std/icap/rfcdiff.patch) version of an [rfcdiff](http://ietf.levkowetz.com/tools/rfcdiff/) tool written by [Henrik Levkowetz](http://www.levkowetz.com/).

Individual errata entries contain entry-specific credits.

