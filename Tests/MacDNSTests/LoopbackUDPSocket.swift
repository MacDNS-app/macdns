// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Minimal bound loopback UDP socket for exchange and pool tests.
final class LoopbackUDPSocket {
    let fd: Int32
    private(set) var address = sockaddr_in()

    init() throws {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw LoopbackError.socketFailed }

        var bindAddress = sockaddr_in()
        bindAddress.sin_family = sa_family_t(AF_INET)
        bindAddress.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
        bindAddress.sin_port = 0
        _ = inet_pton(AF_INET, "127.0.0.1", &bindAddress.sin_addr)

        let bound = withUnsafePointer(to: &bindAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw LoopbackError.bindFailed }

        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        guard named == 0 else { throw LoopbackError.bindFailed }

        var timeout = timeval(tv_sec: 0, tv_usec: 300_000)
        _ = setsockopt(
            fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    deinit {
        Darwin.close(fd)
    }

    func connect(to peer: sockaddr_in) throws {
        var target = peer
        let connected = withUnsafePointer(to: &target) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw LoopbackError.connectFailed }
    }

    func send(_ bytes: [UInt8], to peer: sockaddr_in) {
        var target = peer
        _ = withUnsafePointer(to: &target) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    var port: UInt16 {
        UInt16(bigEndian: address.sin_port)
    }

    func receive() -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: 512)
        let received = recv(fd, &buffer, buffer.count, 0)
        guard received > 0 else { return nil }
        return Array(buffer.prefix(received))
    }

    func receiveWithSender() -> (bytes: [UInt8], sender: sockaddr_in)? {
        var buffer = [UInt8](repeating: 0, count: 512)
        var sender = sockaddr_in()
        var senderLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let received = withUnsafeMutablePointer(to: &sender) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                recvfrom(fd, &buffer, buffer.count, 0, $0, &senderLength)
            }
        }
        guard received > 0 else { return nil }
        return (Array(buffer.prefix(received)), sender)
    }

    enum LoopbackError: Error {
        case socketFailed
        case bindFailed
        case connectFailed
    }
}
