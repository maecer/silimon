import Foundation

func zipResults(resultPaths: [String], archivePath: String, removeFilesAfterZipping: Bool = false) {
    guard !resultPaths.isEmpty else { return }

    let fileManager = FileManager.default
    let directoryPath = fileManager.currentDirectoryPath

    let relativePaths = resultPaths.map { path -> String in
        return (path as NSString).lastPathComponent
    }

    fileManager.changeCurrentDirectoryPath((resultPaths.first! as NSString).deletingLastPathComponent)

    let process = Process()
    process.launchPath = "/usr/bin/zip"
    process.arguments = ["-r", archivePath] + relativePaths
    process.launch()
    process.waitUntilExit()

    if removeFilesAfterZipping {
        for path in resultPaths {
            if fileManager.fileExists(atPath: path) {
                do {
                    try fileManager.removeItem(atPath: path)
                } catch {
                    print("Failed to remove: \(path) - \(error)")
                }
            }
        }
    }

    fileManager.changeCurrentDirectoryPath(directoryPath)
}

func appendToJSONFile(toolOutputs: [String: String], logPath: String) {
    guard jsonOutputEnabled else { return }
    var existingData: [String: String] = [:]

    if let data = FileManager.default.contents(atPath: logPath) {
        if let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: String] {
            existingData = json
        }
    }

    for (key, value) in toolOutputs {
        existingData[key] = value
    }

    if let jsonData = try? JSONSerialization.data(withJSONObject: existingData, options: .prettyPrinted) {
        do {
            try jsonData.write(to: URL(fileURLWithPath: logPath), options: .atomic)
        } catch {
            print("Failed to write JSON data to file: \(error)")
        }
    } else {
        print("Failed to convert dictionary to JSON")
    }
}
