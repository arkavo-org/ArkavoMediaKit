import Foundation

/// Error thrown when an HTTP response exceeds the caller's configured byte budget.
enum BoundedResponseError: Error, Equatable, Sendable {
    case responseTooLarge(limit: Int)
}

extension URLSession {
    /// Streams response bytes incrementally via `URLSession.bytes(for:delegate:)` and aborts
    /// before buffering more than `maxBytes`, checking `expectedContentLength` upfront as well.
    func boundedData(
        for request: URLRequest,
        maxBytes: Int,
        delegate: (any URLSessionTaskDelegate)? = nil
    ) async throws -> (Data, URLResponse) {
        precondition(maxBytes >= 0, "maxBytes must be non-negative")

        let (bytes, response) = try await self.bytes(for: request, delegate: delegate)

        if response.expectedContentLength > Int64(maxBytes) {
            bytes.task.cancel()
            throw BoundedResponseError.responseTooLarge(limit: maxBytes)
        }

        var data = Data()
        if response.expectedContentLength > 0 {
            data.reserveCapacity(min(Int(response.expectedContentLength), min(maxBytes, 64 * 1024)))
        }

        for try await byte in bytes {
            if data.count >= maxBytes {
                bytes.task.cancel()
                throw BoundedResponseError.responseTooLarge(limit: maxBytes)
            }
            data.append(byte)
        }

        return (data, response)
    }
}
