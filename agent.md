# Aegis Relay System: Traffic Normalization Architecture

## Goal
Maintain a stable, low-noise TCP-only tunnel between Bridge and Destination in hostile, stateful inspection environments. The normalization layer ensures the wire profile stays consistent with common browser behavior while keeping the connection resilient under churn.

## Protocol Stack
1. TCP only, no UDP anywhere in the stack.
2. TLS 1.3 as the backbone transport.
3. HTTP/2 (H2) multiplexing over that TLS session.

This yields a single long-lived TLS connection that carries multiple H2 streams, matching modern browser traffic patterns while minimizing connection overhead.

## Traffic Normalization Components

### 1. H2 Multiplexing Over TLS 1.3
- One TLS 1.3 session is established from Bridge to Destination.
- Multiple independent data streams are multiplexed as H2 streams.
- Each local TCP connection maps to one H2 stream.

Benefits:
- Single connection footprint on the wire.
- Stream-level isolation without opening many TCP sessions.
- Matches high-volume browser behavior (H2 + TLS 1.3).

### 2. Connection Cycling (Resilience Logic)
The Bridge maintains the backbone TLS connection but periodically refreshes it to avoid session fatigue and reduce long-lived signature risk.

Policy:
- Rotate when either threshold is reached.
- Threshold A: X minutes since connection creation.
- Threshold B: Y MB transmitted (aggregate in both directions).

Behavior:
1. Mark current TLS connection as draining when thresholds are met.
2. Establish a fresh TLS + H2 backbone.
3. New streams use the new backbone immediately.
4. Draining connection stays alive until all existing streams close.

This prevents hard resets for active streams while steadily refreshing the transport identity.

### 3. Traffic Shaping via Initial Fragmentation
Initial packet fragmentation is used to make the TCP handshake and early TLS records look like standard browser flows.

Mechanism:
- TLS record fragmentation is enforced via a configurable max fragment size.
- The Bridge’s TLS client sends the ClientHello in smaller records rather than a single large frame.
- This approximates browser patterns where the initial handshake is split over multiple TCP packets.

Operational Controls:
- `tls_fragment` size is configurable to tune for target network heuristics.
- Fragmentation applies only to early TLS data to avoid throughput loss.

## Data Flow
1. Local client connects to Bridge TCP listener.
2. Bridge opens or reuses active TLS + H2 backbone.
3. A new H2 stream is created for the client connection.
4. Destination accepts the stream and connects to the configured forward target.
5. Bidirectional relay is performed with flow control and byte accounting.

## Observability and Safety
- All connections are TCP-based with explicit no-UDP enforcement.
- H2 flow control and backpressure are respected to avoid burst signatures.
- Connection cycling is a soft rotation that avoids mid-stream termination.

## Configuration Summary
- Protocol: TLS 1.3 with H2 ALPN.
- Connection Cycling: `rotate_mins` and `rotate_mb`.
- Traffic Shaping: `tls_fragment` for initial TLS record fragmentation.
- TLS Fingerprint: client-side profile selection (Chrome/Firefox/Rustls) to approximate browser JA3.
