import Foundation
import ArgumentParser

final class Atomic<T> {
    private let queue = DispatchQueue(label: "Atomic Serial Queue")
    private var _value: T

    init(_ value: T) {
        self._value = value
    }

    var value: T {
        get { return queue.sync { _value } }
        set { queue.sync { _value = newValue } }
    }
}

struct Silimon: ParsableCommand {
    @Argument(help: "Path to sample (optional; omit to monitor all system activity)")
    var samplePath: String?

    @Option(name: .shortAndLong, help: "Timeout in seconds.")
    var timeout: Int = 60

    @Option(name: .shortAndLong, help: "Run mode options (e.g., 's - static', 'a - aul collection', 'n - network logs', 'e - esf events', 'sane - all').")
    var runmode: String = "sane"

    @Option(name: .shortAndLong, help: "Network interface to capture (e.g., en0).")
    var interface: String = "en0"

    @Option(name: .shortAndLong, help: "Directory to write result files and the zip archive.")
    var outputDir: String = "/tmp"

    @Option(name: [.customShort("f"), .long], help: "Output format ('json', 'sqlite', or 'both').")
    var outputFormat: String = "both"

    var staticAnalysisEnable: Bool = false
    var aulCollectionEnable: Bool = false
    var networkCaptureEnable: Bool = false
    var esfCollectionEnable: Bool = false

    @Flag(name: .shortAndLong, help: "Enable automatic execution. (default: false)")
    var autoExecSample: Bool = false

    @Flag(name: .shortAndLong, help: "Enable debug output. (default: false)")
    var debugOutput: Bool = false

    mutating func run() throws {
        parseRunMode(runmode)
        Silimon.mainArguments = (samplePath, timeout, staticAnalysisEnable, aulCollectionEnable, networkCaptureEnable, esfCollectionEnable, debugOutput, autoExecSample, interface, outputDir, outputFormat)
    }

    mutating func parseRunMode(_ mode: String) {
        for char in mode {
            switch char {
            case "s":
                staticAnalysisEnable = true
            case "a":
                aulCollectionEnable = true
            case "n":
                networkCaptureEnable = true
            case "e":
                esfCollectionEnable = true
            default:
                print("Warning: Unsupported run mode option '\(char)'")
            }
        }
    }

    static var mainArguments: (String?, Int, Bool, Bool, Bool, Bool, Bool, Bool, String, String, String)? = nil
}

func escapeSingleQuotes(_ s: String) -> String {
    return s.replacingOccurrences(of: "'", with: "\\'")
}

func staticAnalysis(_ samplePath: String) -> (String, String) {
    var staticTriage = StaticResults([samplePath])
    do {
        try staticTriage.performStaticAnalysis()
        return (staticTriage.bundleIdentifier, staticTriage.cdHash)
    } catch {
        print("Static analysis failed")
        return ("", "")
    }
}

func startAUL(_ samplePath: String?, bundleIdentifier: String = "", stopFlag: Atomic<Bool>, loggingFlag: Atomic<Bool>) {
    var searchTerms: [String] = []
    if let samplePath = samplePath {
        searchTerms.append((samplePath as NSString).lastPathComponent)
        if !bundleIdentifier.isEmpty {
            searchTerms.append(bundleIdentifier)
        }
    }
    DispatchQueue.global().async {
        var lastSeenDate = Date()
        while !stopFlag.value {
            fetchUnifiedLogs(searchTerms: searchTerms, loggingFlag: loggingFlag, lastSeenDate: &lastSeenDate)
            Thread.sleep(forTimeInterval: 1)
        }
    }
}

func startPacketCapture(_ interface: String, stopFlag: Atomic<Bool>, loggingFlag: Atomic<Bool>, debugOutput: Bool = false) {
    DispatchQueue.global().async {
        let capture = PacketCapture(outputFile: logPaths["packet"]!, outputJSON: logPaths["network"]!, loggingFlag: loggingFlag)
        if debugOutput { print("Started packet capture") }
        capture.startCapture(interface: interface)
        while !stopFlag.value {
            Thread.sleep(forTimeInterval: 0.1)
        }
        capture.stopCapture()
    }
}

func execSample(_ samplePath: String) -> Process {
    let task = Process()
    task.launchPath = "/usr/bin/open"
    if samplePath.hasSuffix(".app") {
        task.arguments = ["-a", samplePath]
    } else {
        task.arguments = [samplePath]
    }
    task.launch()
    return task
}

var logPaths: [String: String] = [:]
var dbManager: DatabaseManager? = nil
var jsonOutputEnabled: Bool = true
var sqliteOutputEnabled: Bool = true

func main() {
    Silimon.main()

    guard let (samplePath, timeout, staticAnalysisFlag, aulCollectionFlag, networkCaptureFlag, esfCollectionFlag, dbgOutput, autoExec, interface, outputDir, outputFormat) = Silimon.mainArguments else {
        print("Error: Failed to parse command-line arguments.")
        return
    }

    jsonOutputEnabled = outputFormat == "json" || outputFormat == "both"
    sqliteOutputEnabled = outputFormat == "sqlite" || outputFormat == "both"

    guard jsonOutputEnabled || sqliteOutputEnabled else {
        print("Error: Invalid output format '\(outputFormat)'. Use 'json', 'sqlite', or 'both'.")
        return
    }

    let timeoutInterval = TimeInterval(timeout)
    let stopFlag = Atomic(false)
    let loggingFlag = Atomic(false)
    let dispatchGroup = DispatchGroup()
    let startTimestamp: String = String(Int64(Date().timeIntervalSince1970 * 1000))
    let sampleName = samplePath.map { ($0 as NSString).lastPathComponent } ?? "system"
    let outputBase = outputDir.hasSuffix("/") ? String(outputDir.dropLast()) : outputDir

    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: outputBase, isDirectory: &isDirectory) else {
        print("Error: output directory '\(outputBase)' does not exist.")
        return
    }
    guard isDirectory.boolValue else {
        print("Error: '\(outputBase)' is not a directory.")
        return
    }
    guard FileManager.default.isWritableFile(atPath: outputBase) else {
        print("Error: output directory '\(outputBase)' is not writable.")
        return
    }

    let logPathGeneric = "\(outputBase)/\(startTimestamp)_\(sampleName)"

    logPaths["sa"] = logPathGeneric + "_sa.json"
    logPaths["main_esf"] = logPathGeneric + "_main_esf.json"
    logPaths["extra_esf"] = logPathGeneric + "_extra_esf.json"
    logPaths["rare_esf"] = logPathGeneric + "_rare_esf.json"
    logPaths["aul"] = logPathGeneric + "_aul.json"
    logPaths["network"] = logPathGeneric + "_nw.json"
    logPaths["packet"] = logPathGeneric + "_packet.pcap"
    logPaths["sqlite"] = logPathGeneric + "_events.sqlite"

    if sqliteOutputEnabled {
        dbManager = DatabaseManager(path: logPaths["sqlite"]!)
    }

    var sIds: (String, String) = ("", "")
    var task: Process? = nil

    if dbgOutput {
        print("Sample Path: \(samplePath ?? "<none>")")
        print("Timeout: \(timeout)")
        print("Run Modes:")
        print("  Static Analysis: \(staticAnalysisFlag)")
        print("  AUL Collection: \(aulCollectionFlag)")
        print("  Network Capture: \(networkCaptureFlag)")
        print("  ESF Collection: \(esfCollectionFlag)")
        print("  Interface: \(interface)")
        print("Sample Auto Execution: \(autoExec)")
        print("Debug Output: \(dbgOutput)")
        print("Output Format: \(outputFormat)")
    }

    if staticAnalysisFlag {
        if let samplePath = samplePath {
            if dbgOutput { print("Running static analysis.") }
            sIds = staticAnalysis(samplePath)
            if sIds.0.isEmpty && sIds.1.isEmpty {
                print("Static analysis limited output.")
            } else if dbgOutput {
                print("Static analysis finished.")
            }
        } else {
            if dbgOutput { print("Skipping static analysis: no sample specified.") }
        }
    }

    if esfCollectionFlag {
        if dbgOutput { print("Starting event monitor.") }
        if sIds.1.isEmpty {
            startRawEventMonitoring(stopFlag: stopFlag, eventSet: 0, dispatchGroup: dispatchGroup)
            startRawEventMonitoring(stopFlag: stopFlag, eventSet: 1, dispatchGroup: dispatchGroup)
            startRawEventMonitoring(stopFlag: stopFlag, eventSet: 2, dispatchGroup: dispatchGroup)
        } else {
            startRawEventMonitoring(stopFlag: stopFlag, eventSet: 0, dispatchGroup: dispatchGroup, sampleHash: sIds.1)
            startRawEventMonitoring(stopFlag: stopFlag, eventSet: 1, dispatchGroup: dispatchGroup, sampleHash: sIds.1)
            startRawEventMonitoring(stopFlag: stopFlag, eventSet: 2, dispatchGroup: dispatchGroup, sampleHash: sIds.1)
        }
    }

    if networkCaptureFlag {
        if dbgOutput { print("Starting packet capture.") }
        startPacketCapture(interface, stopFlag: stopFlag, loggingFlag: loggingFlag, debugOutput: dbgOutput)
    }

    if aulCollectionFlag {
        if dbgOutput { print("Starting AUL logging.") }
        let bundleId = sIds.1.isEmpty ? "" : sIds.0
        startAUL(samplePath, bundleIdentifier: bundleId, stopFlag: stopFlag, loggingFlag: loggingFlag)
    }

    if (aulCollectionFlag || esfCollectionFlag || networkCaptureFlag || autoExec) {
        loggingFlag.value = true

        if dbgOutput { print("Logging enabled. Will give a second to start.") }
        if (aulCollectionFlag || esfCollectionFlag || networkCaptureFlag) {
            Thread.sleep(forTimeInterval: 1)
        }

        if autoExec {
            if let samplePath = samplePath {
                task = execSample(samplePath)
                if dbgOutput { print("Trying to exec sample.") }
            } else {
                if dbgOutput { print("Skipping auto-exec: no sample specified.") }
            }
        }

        let timeoutDate = Date().addingTimeInterval(timeoutInterval)
        let adjustedTimeoutForDispatch: TimeInterval = timeoutInterval * 2

        if dbgOutput { print("Starting Logging - timeout starts now. If manual execution, time to start the sample now.") }

        if autoExec && task != nil && timeout == 0 {
            while task?.isRunning == true {
                Thread.sleep(forTimeInterval: 1)
            }
        } else {
            while Date() < timeoutDate {
                Thread.sleep(forTimeInterval: 1)
            }
        }

        if task?.isRunning == true {
            if dbgOutput { print("Trying to terminate process.") }
            task?.terminate()
        }

        stopFlag.value = true

        if dbgOutput { print("Allow logs to be collected one last time.") }
        Thread.sleep(forTimeInterval: 5)

        if dbgOutput { print("Waiting for tasks to finish") }

        if dispatchGroup.wait(timeout: DispatchTime.now() + adjustedTimeoutForDispatch) == .timedOut {
            if dbgOutput { print("Timeout enforced.") }
        } else {
            if dbgOutput { print("All tasks finished.") }
        }
    }

    if dbgOutput { print("Compressing logs.") }

    dbManager?.close()
    dbManager = nil

    let resultPaths = ["sa", "main_esf", "extra_esf", "rare_esf", "aul", "packet", "network", "sqlite"]
        .compactMap { logPaths[$0] }
        .filter { FileManager.default.fileExists(atPath: $0) }
    zipResults(resultPaths: resultPaths, archivePath: "\(outputBase)/\(startTimestamp)_silimon.zip", removeFilesAfterZipping: true)

    if let sqlitePath = logPaths["sqlite"] {
        for suffix in ["-shm", "-wal"] {
            try? FileManager.default.removeItem(atPath: sqlitePath + suffix)
        }
    }
}

main()
