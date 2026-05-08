import Foundation
import SQLite3

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type?.self)

class DatabaseManager {
    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "silimon.database")

    init(path: String) {
        queue.sync { self.setup(at: path) }
    }

    private func setup(at path: String) {
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            print("Failed to open database: \(dbError())")
            return
        }
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nil, nil, nil)

        let tables = [
            """
            CREATE TABLE IF NOT EXISTS esf_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seq_num INTEGER,
                event_type TEXT,
                process_path TEXT,
                pid INTEGER,
                details TEXT,
                timestamp INTEGER
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS aul_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subsystem TEXT,
                category TEXT,
                message TEXT,
                timestamp INTEGER
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                timestamp INTEGER
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS static_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT,
                value TEXT
            );
            """
        ]
        for stmt in tables {
            if sqlite3_exec(db, stmt, nil, nil, nil) != SQLITE_OK {
                print("Failed to create table: \(dbError())")
            }
        }
    }

    func logESFEvents(_ rows: [(eventType: String, processPath: String, pid: Int, details: String, timestamp: Int, seqNum: Int)]) {
        guard !rows.isEmpty else { return }
        queue.async { [weak self] in
            guard let self, let db = self.db else { return }
            sqlite3_exec(db, "BEGIN;", nil, nil, nil)
            var stmt: OpaquePointer?
            let sql = "INSERT INTO esf_events (seq_num, event_type, process_path, pid, details, timestamp) VALUES (?,?,?,?,?,?);"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
                return
            }
            for row in rows {
                sqlite3_bind_int64(stmt, 1, Int64(row.seqNum))
                sqlite3_bind_text(stmt, 2, row.eventType, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 3, row.processPath, -1, SQLITE_TRANSIENT)
                sqlite3_bind_int64(stmt, 4, Int64(row.pid))
                sqlite3_bind_text(stmt, 5, row.details, -1, SQLITE_TRANSIENT)
                sqlite3_bind_int64(stmt, 6, Int64(row.timestamp))
                sqlite3_step(stmt)
                sqlite3_reset(stmt)
            }
            sqlite3_finalize(stmt)
            sqlite3_exec(db, "COMMIT;", nil, nil, nil)
        }
    }

    func logAULEvent(subsystem: String, category: String, message: String, timestamp: Int) {
        queue.async { [weak self] in
            guard let self, let db = self.db else { return }
            var stmt: OpaquePointer?
            let sql = "INSERT INTO aul_events (subsystem, category, message, timestamp) VALUES (?,?,?,?);"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
            sqlite3_bind_text(stmt, 1, subsystem, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, category, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, message, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int64(stmt, 4, Int64(timestamp))
            sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
    }

    func logNetworkConnections(_ rows: [(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int, timestamp: Int)]) {
        guard !rows.isEmpty else { return }
        queue.async { [weak self] in
            guard let self, let db = self.db else { return }
            sqlite3_exec(db, "BEGIN;", nil, nil, nil)
            var stmt: OpaquePointer?
            let sql = "INSERT INTO network_connections (src_ip, src_port, dst_ip, dst_port, timestamp) VALUES (?,?,?,?,?);"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
                return
            }
            for row in rows {
                sqlite3_bind_text(stmt, 1, row.srcIP, -1, SQLITE_TRANSIENT)
                sqlite3_bind_int64(stmt, 2, Int64(row.srcPort))
                sqlite3_bind_text(stmt, 3, row.dstIP, -1, SQLITE_TRANSIENT)
                sqlite3_bind_int64(stmt, 4, Int64(row.dstPort))
                sqlite3_bind_int64(stmt, 5, Int64(row.timestamp))
                sqlite3_step(stmt)
                sqlite3_reset(stmt)
            }
            sqlite3_finalize(stmt)
            sqlite3_exec(db, "COMMIT;", nil, nil, nil)
        }
    }

    func logStaticAnalysis(key: String, value: String) {
        queue.async { [weak self] in
            guard let self, let db = self.db else { return }
            var stmt: OpaquePointer?
            let sql = "INSERT INTO static_analysis (key, value) VALUES (?,?);"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
            sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, value, -1, SQLITE_TRANSIENT)
            sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
    }

    func close() {
        queue.sync {
            if let db = self.db {
                sqlite3_close(db)
                self.db = nil
            }
        }
    }

    private func dbError() -> String {
        guard let db = db else { return "no database" }
        return String(cString: sqlite3_errmsg(db))
    }

    deinit {
        close()
    }
}
