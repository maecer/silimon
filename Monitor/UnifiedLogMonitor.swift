import Foundation
import OSLog

private let aulLogPath: String = logPaths["aul"]!

func fetchUnifiedLogs(searchTerms: [String], sampleMode: Bool, loggingFlag: Atomic<Bool>, lastSeenDate: inout Date) {
    guard loggingFlag.value else { return }

    var subpredicates = searchTerms.map { NSPredicate(format: "eventMessage CONTAINS %@", $0) }

    if sampleMode {
        // Rebuilt every poll so children FORKed since the last tick are included.
        let pids = ProcessTracker.allTrackedPIDs()
        if !pids.isEmpty {
            subpredicates.append(NSPredicate(format: "processIdentifier IN %@", pids))
        }
    }

    // No-sample mode: searchTerms is empty and no pid predicate is added,
    // so this stays nil and every entry is collected.
    let predicate: NSPredicate? = subpredicates.isEmpty
        ? nil
        : NSCompoundPredicate(orPredicateWithSubpredicates: subpredicates)

    // Recreated per poll: OSLogStore is a snapshot and a long-lived instance
    // does not reliably surface entries written after its creation.
    guard let logStore = try? OSLogStore(scope: .system) else {
        print("Failed to create log store")
        return
    }

    let position = logStore.position(date: lastSeenDate)

    do {
        let sequence = try logStore.getEntries(at: position, matching: predicate)
        var latestDate = lastSeenDate

        for entry in sequence {
            guard let logEntry = entry as? OSLogEntryLog, logEntry.date > lastSeenDate else { continue }

            let pid = Int(logEntry.processIdentifier)
            let messageHash = abs(logEntry.composedMessage.hashValue)
            let key = "\(logEntry.date)_\(messageHash)"
            let value = "\(logEntry.process)[\(pid)] \(logEntry.subsystem): \(logEntry.category) - \(logEntry.composedMessage)"
            appendToJSONFile(toolOutputs: [key: value], logPath: aulLogPath)
            dbManager?.logAULEvent(
                pid: pid,
                process: logEntry.process,
                sender: logEntry.sender,
                subsystem: logEntry.subsystem,
                category: logEntry.category,
                message: logEntry.composedMessage,
                timestamp: Int(logEntry.date.timeIntervalSince1970 * 1000)
            )

            if logEntry.date > latestDate {
                latestDate = logEntry.date
            }
        }

        lastSeenDate = latestDate
    } catch {
        print("Failed to get log entries: \(error)")
    }
}
