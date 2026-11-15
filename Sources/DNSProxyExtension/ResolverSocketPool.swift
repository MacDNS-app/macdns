// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// Pre-connected UDP sockets to the local resolver, so intercepted queries skip
/// per-query socket setup. Resolver-side transaction IDs are allocated
/// sequentially and mapped back to the client's ID on the way out.
///
/// A response is accepted only when it carries the outstanding resolver-side ID
/// and answers that query's Question. Queries without one parsable Question are
/// refused instead of weakening correlation to the transaction ID alone.
final class ResolverSocketPool: @unchecked Sendable {
    private let host: String
    private let port: UInt16
    private let queue: DispatchQueue
    private var sockets: [PooledSocket] = []
    private var isShutdown = false
    private let lock = NSLock()
    private var timeoutTimer: DispatchSourceTimer?

    // Pending queries indexed by resolver-side Transaction ID. Client IDs are
    // restored before responses are returned to the original flow.
    private var pendingQueries: [UInt16: PendingQuery] = [:]
    private var nextResolverTxId: UInt16 = 0

    private struct PendingQuery {
        let clientTxId: UInt16
        let question: DNSQuestion
        let completion: (Data?) -> Void
        let deadlineNanos: UInt64
    }

    static let maxPendingQueries = 2048
    private static let maxResponsesPerWakeup = 64
    private static let sweepInterval: TimeInterval = 0.25

    /// Returns `nil` when the resolver address is not an IPv4 literal or no
    /// socket could be connected, so a pool that would black-hole every query
    /// is never handed out.
    init?(host: String, port: UInt16, poolSize: Int, queue: DispatchQueue) {
        self.host = host
        self.port = port
        self.queue = queue

        var address = in_addr()
        guard inet_pton(AF_INET, host, &address) == 1 else { return nil }

        for _ in 0..<max(poolSize, 0) {
            if let socket = createConnectedSocket(queue: queue) {
                sockets.append(socket)
            }
        }
        guard !sockets.isEmpty else { return nil }

        startTimeoutSweeper()
    }

    deinit {
        lock.lock()
        let needsShutdown = !isShutdown
        lock.unlock()
        if needsShutdown {
            shutdown()
        }
    }

    private func createConnectedSocket(queue: DispatchQueue) -> PooledSocket? {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        if fd < 0 { return nil }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        // Connected so the hot path can use send()/recv() instead of sendto()/recvfrom().
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
            Darwin.close(fd)
            return nil
        }

        let addrLen = socklen_t(addr.sin_len)
        let connectResult = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, addrLen)
            }
        }

        if connectResult < 0 {
            Darwin.close(fd)
            return nil
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)

        let pooledSocket = PooledSocket(fd: fd, source: source)

        source.setEventHandler { [weak self, weak pooledSocket] in
            guard let self = self, let socket = pooledSocket else { return }
            self.handleResponse(on: socket)
        }

        source.setCancelHandler {
            Darwin.close(fd)
        }

        source.resume()

        return pooledSocket
    }

    func query(_ data: Data, timeout: TimeInterval, completion: @escaping (Data?) -> Void) {
        guard let question = DNSResponseCorrelator.question(inQuery: data) else {
            completion(nil)
            return
        }

        lock.lock()
        guard data.count >= 2, !sockets.isEmpty, !isShutdown else {
            lock.unlock()
            completion(nil)
            return
        }

        guard pendingQueries.count < Self.maxPendingQueries else {
            lock.unlock()
            completion(nil)
            return
        }

        let clientTxId = UInt16(data[0]) << 8 | UInt16(data[1])
        guard let resolverTxId = reserveResolverTxId() else {
            lock.unlock()
            completion(nil)
            return
        }

        // Resolver-side IDs are sequential, so this spreads queries round-robin.
        let socketIndex = Int(resolverTxId) % sockets.count
        let socket = sockets[socketIndex]

        let timeoutNanos = UInt64(max(timeout, 0) * 1_000_000_000)
        let deadlineNanos = DispatchTime.now().uptimeNanoseconds &+ timeoutNanos
        pendingQueries[resolverTxId] = PendingQuery(
            clientTxId: clientTxId,
            question: question,
            completion: completion,
            deadlineNanos: deadlineNanos
        )
        lock.unlock()

        var resolverQuery = data
        resolverQuery[0] = UInt8(resolverTxId >> 8)
        resolverQuery[1] = UInt8(resolverTxId & 0x00FF)

        let sent = resolverQuery.withUnsafeBytes { buf in
            send(socket.fd, buf.baseAddress, resolverQuery.count, 0)
        }

        if sent < 0 {
            completeQuery(resolverTxId: resolverTxId, data: nil)
        }
    }

    private func reserveResolverTxId() -> UInt16? {
        for _ in 0...UInt16.max {
            let candidate = nextResolverTxId
            nextResolverTxId &+= 1
            if pendingQueries[candidate] == nil {
                return candidate
            }
        }
        return nil
    }

    private func handleResponse(on socket: PooledSocket) {
        var drained = 0

        while drained < Self.maxResponsesPerWakeup {
            let received = recv(socket.fd, &socket.buffer, socket.buffer.count, 0)

            if received > 2 {
                drained += 1
                let responseData = Data(socket.buffer.prefix(received))
                let txId = UInt16(responseData[0]) << 8 | UInt16(responseData[1])
                completeQuery(resolverTxId: txId, data: responseData)
                continue
            }

            if received < 0 {
                let err = errno
                if err == EAGAIN || err == EWOULDBLOCK || err == EINTR {
                    return
                }
            }

            return
        }

        queue.async { [weak self, weak socket] in
            guard let self = self, let socket = socket else { return }
            self.handleResponse(on: socket)
        }
    }

    private func completeQuery(resolverTxId: UInt16, data: Data?) {
        lock.lock()
        guard let pending = pendingQueries[resolverTxId] else {
            lock.unlock()
            return
        }
        let response = Self.restoringClientTransactionID(pending.clientTxId, in: data)
        if let response,
            !DNSResponseCorrelator.matches(response: response, question: pending.question)
        {
            // Not an answer to the outstanding Question: the query keeps
            // waiting for its real answer until the deadline.
            lock.unlock()
            return
        }
        pendingQueries.removeValue(forKey: resolverTxId)
        lock.unlock()

        pending.completion(response)
    }

    private static func restoringClientTransactionID(_ clientTxId: UInt16, in data: Data?) -> Data? {
        guard var response = data, response.count >= 2 else { return data }
        response[0] = UInt8(clientTxId >> 8)
        response[1] = UInt8(clientTxId & 0x00FF)
        return response
    }

    private func startTimeoutSweeper() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + Self.sweepInterval,
            repeating: Self.sweepInterval,
            leeway: .milliseconds(50)
        )
        timer.setEventHandler { [weak self] in
            self?.expireTimedOutQueries()
        }
        timer.resume()
        timeoutTimer = timer
    }

    private func expireTimedOutQueries() {
        let now = DispatchTime.now().uptimeNanoseconds
        var expired: [PendingQuery] = []
        var expiredIDs: [UInt16] = []

        lock.lock()
        guard !isShutdown else {
            lock.unlock()
            return
        }

        for (txId, pending) in pendingQueries where pending.deadlineNanos <= now {
            expiredIDs.append(txId)
            expired.append(pending)
        }
        for txId in expiredIDs {
            pendingQueries.removeValue(forKey: txId)
        }
        lock.unlock()

        for query in expired {
            query.completion(nil)
        }
    }

    func shutdown() {
        lock.lock()
        guard !isShutdown else {
            lock.unlock()
            return
        }
        isShutdown = true
        let socketsToClose = sockets
        sockets.removeAll()
        let pending = pendingQueries
        pendingQueries.removeAll()
        let timer = timeoutTimer
        timeoutTimer = nil
        lock.unlock()

        for (_, query) in pending {
            query.completion(nil)
        }

        timer?.cancel()

        for socket in socketsToClose {
            socket.source.cancel()
        }
    }

    private final class PooledSocket: @unchecked Sendable {
        let fd: Int32
        let source: DispatchSourceRead
        // Preallocated per socket so the hot path does not allocate.
        var buffer = [UInt8](repeating: 0, count: 4096)

        init(fd: Int32, source: DispatchSourceRead) {
            self.fd = fd
            self.source = source
        }
    }
}
