import Foundation

// WIP
protocol staticTool {
    var tool: String { get }
    var path: String { get set }
    var description: String { get }
    mutating func setPath()
}

enum toolArgs: Hashable, CustomStringConvertible {
    case file, md5, sha256, stat, codesign, otool_shared_libs, codesign_entitlements, nm_imports

    var description: String {
        switch self {
        case .file: return "file"
        case .md5: return "md5"
        case .sha256: return "sha256"
        case .stat: return "stat"
        case .codesign: return "codesign"
        case .otool_shared_libs: return "otool_shared_libs"
        case .codesign_entitlements: return "codesign_entitlements"
        case .nm_imports: return "nm_imports"
        }
    }

    func returnArgs() -> [String] {
        switch self {
        case .sha256: return ["-a", "256"]
        case .codesign: return ["-dvvv"]
        case .otool_shared_libs: return ["-L"]
        case .codesign_entitlements: return ["-d", "--entitlements", "-"]
        case .nm_imports: return ["-u"]
        default: return []
        }
    }
}

struct StaticResults {
    let sample: [String]
    var logPath: String = "static.json"
    let localTooling: [toolArgs: String] = [
        .md5: "md5", .sha256: "shasum", .stat: "stat",
        .codesign: "codesign", .otool_shared_libs: "otool",
        .codesign_entitlements: "codesign", .nm_imports: "nm"
    ]
    // var customTooling: [String: String]?
    let nonDirectoryTooling: [String] = ["md5", "shasum", "otool", "nm"]
    var sha256 = "", bundleIdentifier = "", cdHash = "", fileType = "", fileSize = ""

    init(_ sample: [String]) {
        self.sample = sample
        self.logPath = logPaths["sa"]!
    }

    mutating func performStaticAnalysis() throws {
        runFile()
        for (toolA, name) in self.localTooling {
            let path = setPath(name)
            if !path.isEmpty {
                if self.fileType == "directory" && nonDirectoryTooling.contains(name) {
                    if let appName = self.sample[0].split(separator: "/").last?.split(separator: ".").first {
                        let sampleNew = "\(self.sample[0])/Contents/MacOS/\(appName)"
                        runTool(toolA, path: path, sampleNew: [sampleNew])
                    }
                } else {
                    runTool(toolA, path: path)
                }
            } else {
                continue
            }
        }
    }

    mutating private func runFile() {
        runTool(toolArgs.file, path: setPath("file"))
    }

    mutating private func runTool(_ tool: toolArgs, path: String, sampleNew: [String] = []) {
        let process = Process()
        var args: [String]
        let sample: [String] = sampleNew.isEmpty ? self.sample : sampleNew

        process.executableURL = URL(fileURLWithPath: path)

        let lta = tool.returnArgs()
        if !lta.isEmpty {
            args = lta + sample
        } else {
            args = sample
        }

        process.arguments = args

        let pipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = pipe
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            let errorOutput = String(data: errorData, encoding: .utf8) ?? ""

            if !output.isEmpty {
                if tool != .file {
                    appendToJSONFile(toolOutputs: [tool.description: output], logPath: self.logPath)
                    dbManager?.logStaticAnalysis(key: tool.description, value: output)
                }
            } else if !errorOutput.isEmpty {
                appendToJSONFile(toolOutputs: [tool.description: errorOutput], logPath: self.logPath)
                dbManager?.logStaticAnalysis(key: tool.description, value: errorOutput)
            } else {
                return
            }

            switch tool {
            case .sha256:
                self.sha256 = output.components(separatedBy: " ")[0]
            case .codesign:
                let codeSignArtifacts = extractValues(from: errorOutput)
                self.bundleIdentifier = codeSignArtifacts.identifier ?? ""
                self.cdHash = codeSignArtifacts.cdHash ?? ""
            case .file:
                self.fileType = output.components(separatedBy: ":")[1].trimmingCharacters(in: .whitespacesAndNewlines)
                appendToJSONFile(toolOutputs: ["file": self.fileType], logPath: self.logPath)
                dbManager?.logStaticAnalysis(key: "file", value: self.fileType)
            case .stat:
                self.fileSize = output.components(separatedBy: " ")[7]
                appendToJSONFile(toolOutputs: ["size": self.fileSize], logPath: self.logPath)
                dbManager?.logStaticAnalysis(key: "size", value: self.fileSize)
            default:
                break
            }
        } catch {
            print("An error occurred: \(error)")
        }
    }

    private mutating func setPath(_ tool: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = [tool]

        let pipe = Pipe()
        process.standardOutput = pipe

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            if !output.isEmpty {
                return output.trimmingCharacters(in: .whitespacesAndNewlines)
            } else {
                return ""
            }
        } catch {
            print("An error occurred: \(error)")
            return ""
        }
    }
}
