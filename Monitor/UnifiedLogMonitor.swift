import Foundation
import OSLog

private let aulLogPath: String = logPaths["aul"]!

func fetchUnifiedLogs(searchTerms: [String], loggingFlag: Atomic<Bool>, lastSeenDate: inout Date) {
    guard loggingFlag.value else { return }

    let subpredicates = searchTerms.map { NSPredicate(format: "eventMessage CONTAINS %@", $0) }
    let predicate = NSCompoundPredicate(orPredicateWithSubpredicates: subpredicates)

    guard let logStore = try? OSLogStore(scope: .system) else {
        print("Failed to create log store")
        return
    }

    let position = logStore.position(date: lastSeenDate)

    do {
        let sequence = try logStore.getEntries(at: position, matching: predicate)
        var latestDate = lastSeenDate

        for entry in sequence {
            if let logEntry = entry as? OSLogEntryLog {
                if logEntry.date <= lastSeenDate { continue }

                let messageHash = abs(logEntry.composedMessage.hashValue)
                let key = "\(logEntry.date)_\(messageHash)"
                let value = "\(logEntry.subsystem): \(logEntry.category) - \(logEntry.composedMessage)"
                appendToJSONFile(toolOutputs: [key: value], logPath: aulLogPath)

                if logEntry.date > latestDate {
                    latestDate = logEntry.date
                }
            }
        }

        lastSeenDate = latestDate
    } catch {
        print("Failed to get log entries: \(error)")
    }
}
