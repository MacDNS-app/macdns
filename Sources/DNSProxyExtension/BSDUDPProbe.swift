// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

enum BSDUDPProbe {
    static func exchange(
        query: Data, address: sockaddr_in, timeout: TimeInterval
    ) -> Result<Data, ProxyProbeFailure> {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return .failure(.init(stage: .socket, reason: .systemError(errno))) }
        defer { Darwin.close(fd) }

        guard timeout > 0 else { return .failure(.init(stage: .readBody, reason: .timeout)) }
        let microseconds = max(1, Int(timeout * 1_000_000))
        var receiveTimeout = timeval(
            tv_sec: microseconds / 1_000_000, tv_usec: __darwin_suseconds_t(microseconds % 1_000_000))
        guard
            setsockopt(
                fd, SOL_SOCKET, SO_RCVTIMEO, &receiveTimeout,
                socklen_t(MemoryLayout<timeval>.size)) == 0
        else { return .failure(.init(stage: .socket, reason: .systemError(errno))) }

        var address = address
        let connected = withUnsafePointer(to: &address) { addressPointer in
            addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else {
            return .failure(.init(stage: .connect, reason: .systemError(errno)))
        }

        let sent = query.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, query.count, 0) }
        guard sent == query.count else {
            return .failure(
                .init(stage: .send, reason: sent < 0 ? .systemError(errno) : .shortWrite))
        }

        var buffer = [UInt8](repeating: 0, count: 512)
        let received = Darwin.recv(fd, &buffer, buffer.count, 0)
        guard received > 0 else {
            let code = errno
            let reason: ProxyProbeFailure.Reason =
                received == 0 ? .invalidResponse : (code == EAGAIN ? .timeout : .systemError(code))
            return .failure(.init(stage: .readBody, reason: reason))
        }
        return .success(Data(buffer.prefix(received)))
    }
}
