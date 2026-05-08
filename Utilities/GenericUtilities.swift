import Foundation

func extractValues(from input: String) -> (identifier: String?, format: String?, cdHash: String?) {
    let identifierPattern = "Identifier=([\\w.-]+)"
    let formatPattern = "Format=([\\w\\-\\(\\) ]+)"
    let cdHashPattern = "CDHash=([a-fA-F0-9]+)"

    let identifier = matchRegex(pattern: identifierPattern, in: input)
    let format = matchRegex(pattern: formatPattern, in: input)
    let cdHash = matchRegex(pattern: cdHashPattern, in: input)

    return (identifier, format, cdHash)
}

func matchRegex(pattern: String, in text: String) -> String? {
    do {
        let regex = try NSRegularExpression(pattern: pattern, options: [])
        let nsString = text as NSString
        let results = regex.matches(in: text, options: [], range: NSMakeRange(0, nsString.length))

        if let match = results.first {
            return nsString.substring(with: match.range(at: 1))
        }
    } catch let error {
        print("Invalid regex: \(error.localizedDescription)")
    }
    return nil
}
