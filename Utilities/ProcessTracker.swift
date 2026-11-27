import Foundation

enum ProcessTracker {
    private static let lock = NSLock()
    private static var activePIDs: Set<pid_t> = []
    // Never pruned: AUL entries can flush after a child exits, and ESF's
    // active set would already have dropped the pid by then.
    private static var everTrackedPIDs: Set<pid_t> = []
    private static var _sampleFound = false

    static var sampleFound: Bool {
        lock.lock(); defer { lock.unlock() }
        return _sampleFound
    }

    static func foundSample(pid: pid_t) {
        lock.lock(); defer { lock.unlock() }
        _sampleFound = true
        activePIDs.insert(pid)
        everTrackedPIDs.insert(pid)
    }

    static func track(_ pid: pid_t) {
        lock.lock(); defer { lock.unlock() }
        activePIDs.insert(pid)
        everTrackedPIDs.insert(pid)
    }

    static func untrack(_ pid: pid_t) {
        lock.lock(); defer { lock.unlock() }
        activePIDs.remove(pid)
    }

    static func isActive(_ pid: pid_t) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return activePIDs.contains(pid)
    }

    static func allTrackedPIDs() -> [Int] {
        lock.lock(); defer { lock.unlock() }
        return everTrackedPIDs.map(Int.init)
    }
}
