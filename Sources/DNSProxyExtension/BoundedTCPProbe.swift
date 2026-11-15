// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// One absolute monotonic deadline shared by connect, send and every read of a
/// single probe.
///
/// Socket options cannot express this: on Darwin `SO_SNDTIMEO` does not apply to
/// `connect` (XNU's initial TCP timeout is ~75s), and `SO_RCVTIMEO` is an
/// inactivity timeout, so a peer dribbling one byte at a time restarts the
/// window on every partial read.
struct ProbeDeadline {
    private let expiresAtUptimeNanoseconds: UInt64

    init(timeout: TimeInterval, now: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        expiresAtUptimeNanoseconds = now &+ UInt64(max(0, timeout) * 1_000_000_000)
    }

    /// Milliseconds left, or nil once the deadline has passed.
    func remainingMilliseconds(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> Int32? {
        guard now < expiresAtUptimeNanoseconds else { return nil }
        let remaining = (expiresAtUptimeNanoseconds - now + 999_999) / 1_000_000
        return Int32(min(remaining, UInt64(Int32.max)))
    }
}

enum ProbeWaitOutcome {
    case ready
    /// Interrupted (EINTR): recompute the deadline and wait again.
    case retry
    case timedOut
    case failed
}

/// Non-blocking socket operations the bounded probe needs. Injectable so the
/// deadline behaviour is verifiable without a real peer.
protocol BoundedTCPProbeTransport: AnyObject {
    var failureReason: ProxyProbeFailure.Reason { get }
    /// Starts a non-blocking connect. False on immediate failure.
    func startConnect() -> Bool
    func waitWritable(milliseconds: Int32) -> ProbeWaitOutcome
    /// `SO_ERROR` once the socket reports writable. 0 means connected.
    func pendingConnectError() -> Int32
    /// Bytes written, 0 to retry after another wait, negative on error.
    func send(_ data: Data) -> Int
    func waitReadable(milliseconds: Int32) -> ProbeWaitOutcome
    /// Bytes read. An empty value means retry after another wait. Nil signals a
    /// fatal error or an orderly close before the expected length arrived.
    func receive(maxLength: Int) -> Data?
    func close()
}

/// Performs one DNS-over-TCP exchange entirely inside a single absolute
/// deadline, so the caller's `DispatchGroup.wait()`, and the NE stop completion
/// queued behind it, stay bounded.
enum BoundedTCPProbe {
    static func exchange(
        transport: BoundedTCPProbeTransport, query: Data, deadline: ProbeDeadline,
        maxResponseBytes: Int
    ) -> Result<Data, ProxyProbeFailure> {
        defer { transport.close() }
        guard transport.startConnect() else {
            return .failure(.init(stage: .connect, reason: transport.failureReason))
        }
        if let failure = waitFailure(
            deadline: deadline, transport: transport, wait: transport.waitWritable)
        {
            return .failure(.init(stage: .connect, reason: failure))
        }
        let connectError = transport.pendingConnectError()
        guard connectError == 0 else {
            return .failure(.init(stage: .connect, reason: .systemError(connectError)))
        }

        // DNS-over-TCP: 2-byte big-endian length prefix.
        var framed = Data([UInt8(query.count >> 8), UInt8(query.count & 0xFF)])
        framed.append(query)
        var written = 0
        while written < framed.count {
            if let failure = waitFailure(
                deadline: deadline, transport: transport, wait: transport.waitWritable)
            {
                return .failure(.init(stage: .send, reason: failure))
            }
            let count = transport.send(Data(framed.dropFirst(written)))
            guard count >= 0 else {
                return .failure(.init(stage: .send, reason: transport.failureReason))
            }
            written += count
        }

        let lengthPrefix: Data
        switch receive(2, transport: transport, deadline: deadline, stage: .readLength) {
        case .success(let prefix): lengthPrefix = prefix
        case .failure(let failure): return .failure(failure)
        }
        let responseLength = Int(lengthPrefix[0]) << 8 | Int(lengthPrefix[1])
        guard responseLength > 0, responseLength <= maxResponseBytes else {
            return .failure(.init(stage: .readLength, reason: .invalidResponseLength))
        }
        return receive(responseLength, transport: transport, deadline: deadline, stage: .readBody)
    }

    private static func waitFailure(
        deadline: ProbeDeadline, transport: BoundedTCPProbeTransport,
        wait: (Int32) -> ProbeWaitOutcome
    ) -> ProxyProbeFailure.Reason? {
        while true {
            guard let milliseconds = deadline.remainingMilliseconds() else { return .timeout }
            switch wait(milliseconds) {
            case .ready: return nil
            case .retry: continue
            case .timedOut: return .timeout
            case .failed: return transport.failureReason
            }
        }
    }

    private static func receive(
        _ count: Int, transport: BoundedTCPProbeTransport, deadline: ProbeDeadline,
        stage: ProxyProbeFailure.Stage
    ) -> Result<Data, ProxyProbeFailure> {
        var received = Data()
        received.reserveCapacity(count)
        while received.count < count {
            if let failure = waitFailure(
                deadline: deadline, transport: transport, wait: transport.waitReadable)
            {
                return .failure(.init(stage: stage, reason: failure))
            }
            guard let chunk = transport.receive(maxLength: count - received.count) else {
                return .failure(.init(stage: stage, reason: transport.failureReason))
            }
            received.append(chunk)
        }
        return .success(received)
    }
}

/// BSD-socket transport: non-blocking descriptor driven by `poll` and `SO_ERROR`.
final class BSDBoundedTCPProbeTransport: BoundedTCPProbeTransport {
    private var descriptor: Int32
    private var address: sockaddr_in
    private(set) var failureReason = ProxyProbeFailure.Reason.unavailable

    init(address: sockaddr_in) throws {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            throw ProxyProbeFailure(stage: .socket, reason: .systemError(errno))
        }
        guard BSDBoundedTCPProbeTransport.configureSocket(fd) else {
            let code = errno
            Darwin.close(fd)
            throw ProxyProbeFailure(stage: .socket, reason: .systemError(code))
        }
        self.descriptor = fd
        self.address = address
    }

    /// `SO_NOSIGPIPE` before anything else: a resolver restart can reset the
    /// connection mid-probe, and without it `send()` raises `SIGPIPE`, whose
    /// default disposition terminates the DNS Proxy. With it the probe just sees
    /// `EPIPE` and fails like any other probe error.
    static func configureSocket(_ fd: Int32) -> Bool {
        var one: Int32 = 1
        guard
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0
        else {
            return false
        }
        let flags = fcntl(fd, F_GETFL, 0)
        return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0
    }

    deinit {
        close()
    }

    func startConnect() -> Bool {
        guard descriptor >= 0 else {
            failureReason = .systemError(EBADF)
            return false
        }
        let result = withUnsafePointer(to: &address) { addressPointer in
            addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result != 0, errno != EINPROGRESS else { return true }
        failureReason = .systemError(errno)
        return false
    }

    func waitWritable(milliseconds: Int32) -> ProbeWaitOutcome {
        wait(for: Int16(POLLOUT), milliseconds: milliseconds)
    }

    func waitReadable(milliseconds: Int32) -> ProbeWaitOutcome {
        wait(for: Int16(POLLIN), milliseconds: milliseconds)
    }

    func pendingConnectError() -> Int32 {
        guard descriptor >= 0 else { return EBADF }
        var value: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &value, &length) == 0 else {
            return errno
        }
        return value
    }

    func send(_ data: Data) -> Int {
        guard descriptor >= 0, !data.isEmpty else {
            failureReason = .systemError(descriptor < 0 ? EBADF : EINVAL)
            return -1
        }
        let count = data.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, data.count, 0) }
        if count < 0 {
            let code = errno
            if code == EAGAIN || code == EINTR { return 0 }
            failureReason = .systemError(code)
        }
        return count
    }

    func receive(maxLength: Int) -> Data? {
        guard descriptor >= 0, maxLength > 0 else {
            failureReason = .systemError(descriptor < 0 ? EBADF : EINVAL)
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: maxLength)
        let count = Darwin.recv(descriptor, &buffer, maxLength, 0)
        if count > 0 { return Data(buffer.prefix(count)) }
        if count == 0 {
            failureReason = .connectionClosed
            return nil
        }
        let code = errno
        if code == EAGAIN || code == EINTR { return Data() }
        failureReason = .systemError(code)
        return nil
    }

    func close() {
        guard descriptor >= 0 else { return }
        Darwin.close(descriptor)
        descriptor = -1
    }

    private func wait(for events: Int16, milliseconds: Int32) -> ProbeWaitOutcome {
        guard descriptor >= 0 else {
            failureReason = .systemError(EBADF)
            return .failed
        }
        var descriptors = pollfd(fd: descriptor, events: events, revents: 0)
        let result = Darwin.poll(&descriptors, 1, milliseconds)
        if result == 0 { return .timedOut }
        if result < 0 {
            let code = errno
            if code == EINTR { return .retry }
            failureReason = .systemError(code)
            return .failed
        }
        if descriptors.revents & Int16(POLLNVAL) != 0 {
            failureReason = .systemError(EBADF)
            return .failed
        }
        // POLLHUP can accompany readable data, so only fail when the requested
        // event is absent.
        if descriptors.revents & Int16(POLLERR | POLLHUP) != 0,
            descriptors.revents & events == 0
        {
            let code = pendingConnectError()
            failureReason = code == 0 ? .connectionClosed : .systemError(code)
            return .failed
        }
        return .ready
    }
}
