import Foundation

class PacketCapture {
    var pcapHandle: OpaquePointer?
    var pcapDumper: OpaquePointer?
    var packetCount: Int = 0
    let outputFile: String
    let outputJSON: String
    let loggingFlag: Atomic<Bool>

    private var pendingWrites: [String: String] = [:]
    private let writeQueue = DispatchQueue(label: "silimon.network.write")
    private static let flushThreshold = 50

    init(outputFile: String, outputJSON: String, loggingFlag: Atomic<Bool>) {
        self.outputFile = outputFile
        self.outputJSON = outputJSON
        self.loggingFlag = loggingFlag
    }

    func startCapture(interface: String) {
        var errbuf = [Int8](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        pcapHandle = pcap_open_live(interface, 65535, 1, 1000, &errbuf)

        guard let _ = pcapHandle else {
            print("Error opening interface: \(String(cString: errbuf))")
            return
        }

        pcapDumper = pcap_dump_open_append(pcapHandle, outputFile)

        guard let _ = pcapDumper else {
            print("Error opening output file: \(String(cString: errbuf))")
            if let handle = pcapHandle {
                pcap_close(handle)
            }
            return
        }

        while !loggingFlag.value {
            Thread.sleep(forTimeInterval: 0.1)
        }

        let selfPointer = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
        pcap_loop(self.pcapHandle, -1, { (userData, header, packet) in
            let instance = Unmanaged<PacketCapture>.fromOpaque(userData!).takeUnretainedValue()
            instance.packetHandler(header: header, packet: packet)
        }, selfPointer)

        writeQueue.sync { flush() }

        if let dumper = pcapDumper {
            pcap_dump_flush(dumper)
            pcap_dump_close(dumper)
        }
        if let handle = pcapHandle {
            pcap_close(handle)
        }
        pcapDumper = nil
        pcapHandle = nil
    }

    func stopCapture() {
        if let handle = pcapHandle {
            pcap_breakloop(handle)
        }
    }

    private func flush() {
        guard !pendingWrites.isEmpty else { return }
        appendToJSONFile(toolOutputs: pendingWrites, logPath: outputJSON)
        pendingWrites.removeAll()
    }

    func packetHandler(header: UnsafePointer<pcap_pkthdr>?, packet: UnsafePointer<u_char>?) {
        guard let header = header, let packet = packet else { return }

        self.packetCount += 1

        let rawPointer = UnsafeMutableRawPointer(self.pcapDumper)
        let mutablePointer = rawPointer?.assumingMemoryBound(to: u_char.self)
        pcap_dump(mutablePointer, header, packet)

        let etherHeaderLength = 14
        if header.pointee.caplen >= etherHeaderLength + 20 {
            let ipHeaderOffset = etherHeaderLength
            let ipHeader = packet + ipHeaderOffset

            let etherType = (packet + 12).withMemoryRebound(to: UInt16.self, capacity: 1) { $0.pointee.bigEndian }

            var sourceIPString: String?
            var destinationIPString: String?
            var ipProtocol: UInt8 = 0
            var transportHeaderOffset: Int = 0

            if etherType == 0x0800 {
                // IPv4
                let protocolOffset = ipHeaderOffset + 9
                ipProtocol = packet[protocolOffset]

                let sourceIP = (ipHeader + 12).withMemoryRebound(to: UInt8.self, capacity: 4) { $0 }
                let destinationIP = (ipHeader + 16).withMemoryRebound(to: UInt8.self, capacity: 4) { $0 }

                sourceIPString = String(format: "%d.%d.%d.%d", sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3])
                destinationIPString = String(format: "%d.%d.%d.%d", destinationIP[0], destinationIP[1], destinationIP[2], destinationIP[3])

                let ipHeaderLength = Int((packet[ipHeaderOffset] & 0x0F) * 4)
                transportHeaderOffset = ipHeaderOffset + ipHeaderLength

            } else if etherType == 0x86DD {
                // IPv6 — fixed 40-byte header
                guard header.pointee.caplen >= etherHeaderLength + 40 else { return }
                ipProtocol = packet[ipHeaderOffset + 6]

                // Source address: bytes 8-23, Destination address: bytes 24-39
                var srcParts = [String]()
                var dstParts = [String]()
                for i in 0..<8 {
                    let srcWord = (UInt16(packet[ipHeaderOffset + 8 + i * 2]) << 8) | UInt16(packet[ipHeaderOffset + 9 + i * 2])
                    srcParts.append(String(srcWord, radix: 16))
                    let dstWord = (UInt16(packet[ipHeaderOffset + 24 + i * 2]) << 8) | UInt16(packet[ipHeaderOffset + 25 + i * 2])
                    dstParts.append(String(dstWord, radix: 16))
                }
                sourceIPString = srcParts.joined(separator: ":")
                destinationIPString = dstParts.joined(separator: ":")

                transportHeaderOffset = ipHeaderOffset + 40
            }

            if let srcIP = sourceIPString, let dstIP = destinationIPString,
               (ipProtocol == 6 || ipProtocol == 17) {
                // TCP or UDP
                guard header.pointee.caplen >= transportHeaderOffset + 4 else { return }
                let sourcePort = (packet + transportHeaderOffset).withMemoryRebound(to: UInt16.self, capacity: 1) { $0.pointee.bigEndian }
                let destinationPort = (packet + transportHeaderOffset + 2).withMemoryRebound(to: UInt16.self, capacity: 1) { $0.pointee.bigEndian }

                let uniqueIdentifier = "\(header.pointee.ts.tv_sec)-\(header.pointee.ts.tv_usec)-\(srcIP)-\(dstIP)-\(sourcePort)-\(destinationPort)-\(header.pointee.len)"
                let entry = srcIP + ":" + String(sourcePort) + "->" + dstIP + ":" + String(destinationPort)
                writeQueue.async { [weak self] in
                    guard let self = self else { return }
                    self.pendingWrites[uniqueIdentifier] = entry
                    if self.pendingWrites.count >= PacketCapture.flushThreshold {
                        self.flush()
                    }
                }
            }
        }
    }

    deinit {
        if pcapHandle != nil {
            stopCapture()
        }
        if let dumper = pcapDumper {
            pcap_dump_flush(dumper)
            pcap_dump_close(dumper)
            pcapDumper = nil
        }
        if let handle = pcapHandle {
            pcap_close(handle)
            pcapHandle = nil
        }
    }
}
