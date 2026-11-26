import Foundation
import zlib

/// Raw deflate, one stream per file (SPEC.md 2.3). Not thread-safe: owned by the writer queue.
final class Deflater {
    private let stream: UnsafeMutablePointer<z_stream>
    private var ended = false
    private(set) var output = Data()

    init(level: Int32 = 6, memLevel: Int32 = 8) throws {
        stream = .allocate(capacity: 1)
        stream.initialize(to: z_stream())
        let r = deflateInit2_(stream, level, Z_DEFLATED, -15, memLevel, Z_DEFAULT_STRATEGY,
                              zlibVersion(), Int32(MemoryLayout<z_stream>.size))
        guard r == Z_OK else {
            ended = true // deinit frees the allocation
            throw DeflateError.init_(r)
        }
    }

    deinit {
        if !ended { deflateEnd(stream) }
        stream.deinitialize(count: 1)
        stream.deallocate()
    }

    enum DeflateError: Error { case init_(Int32), stream(Int32) }

    /// Compresses `input` without flushing; output accumulates in `output`.
    func write(_ input: Data) throws { try run(input, flush: Z_NO_FLUSH) }

    /// Z_SYNC_FLUSH; returns and clears everything produced since the last take.
    func sync() throws -> Data {
        try run(Data(), flush: Z_SYNC_FLUSH)
        return takeOutput()
    }

    /// Z_FINISH; returns and clears the remaining output. The stream is unusable after this.
    func finish() throws -> Data {
        try run(Data(), flush: Z_FINISH)
        return takeOutput()
    }

    var pendingOutputCount: Int { output.count }

    func takeOutput() -> Data {
        let o = output
        output = Data()
        return o
    }

    private func run(_ input: Data, flush: Int32) throws {
        guard !ended else { throw DeflateError.stream(Z_STREAM_ERROR) }
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        try input.withUnsafeBytes { (inBuf: UnsafeRawBufferPointer) in
            stream.pointee.next_in = UnsafeMutablePointer(mutating: inBuf.bindMemory(to: Bytef.self).baseAddress)
            stream.pointee.avail_in = uInt(inBuf.count)
            while true {
                let (r, produced): (Int32, Int) = chunk.withUnsafeMutableBufferPointer { out in
                    stream.pointee.next_out = out.baseAddress
                    stream.pointee.avail_out = uInt(out.count)
                    let r = deflate(stream, flush)
                    return (r, out.count - Int(stream.pointee.avail_out))
                }
                if produced > 0 { output.append(contentsOf: chunk[0..<produced]) }
                if flush == Z_FINISH {
                    if r == Z_STREAM_END {
                        deflateEnd(stream)
                        ended = true
                        break
                    }
                    guard r == Z_OK || r == Z_BUF_ERROR else { throw DeflateError.stream(r) }
                    continue
                }
                guard r == Z_OK || r == Z_BUF_ERROR else { throw DeflateError.stream(r) }
                // Done when all input is consumed and deflate had spare output room.
                if stream.pointee.avail_in == 0 && stream.pointee.avail_out != 0 { break }
            }
            stream.pointee.next_in = nil
            stream.pointee.avail_in = 0
        }
    }
}

/// Raw inflate that accepts an unfinished stream and caps the output.
enum Inflate {
    struct Result {
        var output: Data
        var capped: Bool
        var error: Bool
        var finished: Bool
    }

    static func inflate(_ input: Data, cap: Int = Format.inflateCap) -> Result {
        var s = z_stream()
        guard inflateInit2_(&s, -15, zlibVersion(), Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            return Result(output: Data(), capped: false, error: true, finished: false)
        }
        defer { inflateEnd(&s) }
        var out = Data()
        var capped = false
        var error = false
        var finished = false
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        input.withUnsafeBytes { (inBuf: UnsafeRawBufferPointer) in
            s.next_in = UnsafeMutablePointer(mutating: inBuf.bindMemory(to: Bytef.self).baseAddress)
            s.avail_in = uInt(inBuf.count)
            while true {
                let (r, produced): (Int32, Int) = chunk.withUnsafeMutableBufferPointer { o in
                    s.next_out = o.baseAddress
                    s.avail_out = uInt(o.count)
                    let r = zlib.inflate(&s, Z_SYNC_FLUSH)
                    return (r, o.count - Int(s.avail_out))
                }
                if produced > 0 {
                    let room = cap - out.count
                    if produced > room {
                        out.append(contentsOf: chunk[0..<max(0, room)])
                        capped = true
                        return
                    }
                    out.append(contentsOf: chunk[0..<produced])
                }
                if r == Z_STREAM_END { finished = true; return }
                if r == Z_BUF_ERROR { return } // no progress possible: input used up (unfinished stream)
                if r != Z_OK { error = true; return }
                if s.avail_in == 0 && s.avail_out != 0 { return }
            }
        }
        return Result(output: out, capped: capped, error: error, finished: finished)
    }
}
