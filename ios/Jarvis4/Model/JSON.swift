// A JSON value as the router sends it. The router's shapes (docs/API.md) grow fields over time and a few carry mixed
// types, so the app reads them through this lenient value instead of strict Codable structs: an unknown or
// differently-typed field never fails a whole list. Nothing signed is read this way: what the phone signs is decoded
// and checked by CoreCrypto / Checks from the core's signed payload bytes.
import Foundation

enum JSON: Decodable, Equatable, Hashable, Sendable {
  case null, bool(Bool), number(Double), string(String), array([JSON]), object([String: JSON])

  init(from decoder: Decoder) throws {
    let c = try decoder.singleValueContainer()
    if c.decodeNil() { self = .null }
    else if let b = try? c.decode(Bool.self) { self = .bool(b) }
    else if let n = try? c.decode(Double.self) { self = .number(n) }
    else if let s = try? c.decode(String.self) { self = .string(s) }
    else if let a = try? c.decode([JSON].self) { self = .array(a) }
    else if let o = try? c.decode([String: JSON].self) { self = .object(o) }
    else { self = .null }
  }

  static func parse(_ data: Data) -> JSON { (try? JSONDecoder().decode(JSON.self, from: data)) ?? .null }

  subscript(key: String) -> JSON {
    if case .object(let o) = self { return o[key] ?? .null }
    return .null
  }

  var string: String? {
    switch self {
    case .string(let s): s
    case .number(let n): n == n.rounded() && abs(n) < 1e15 ? String(Int(n)) : String(n)
    case .bool(let b): b ? "true" : "false"
    default: nil
    }
  }
  /// a string that is there and not empty
  var text: String? { string.flatMap { $0.isEmpty ? nil : $0 } }
  var double: Double? {
    switch self {
    case .number(let n): n
    case .string(let s): Double(s)
    default: nil
    }
  }
  var int: Int? { double.map { Int($0) } }
  var bool: Bool? {
    switch self {
    case .bool(let b): b
    case .number(let n): n != 0
    default: nil
    }
  }
  var array: [JSON] { if case .array(let a) = self { return a }; return [] }
  var object: [String: JSON]? { if case .object(let o) = self { return o }; return nil }
  var isNull: Bool { self == .null }
  var strings: [String] { array.compactMap(\.string) }

  /// a Foundation value for JSONSerialization (request bodies, the signed-options comparison on review pages)
  var any: Any {
    switch self {
    case .null: NSNull()
    case .bool(let b): b
    case .number(let n): n == n.rounded() && abs(n) < 1e15 ? Int(n) as Any : n as Any
    case .string(let s): s
    case .array(let a): a.map(\.any)
    case .object(let o): o.mapValues(\.any)
    }
  }
  var anyObject: [String: Any] { (any as? [String: Any]) ?? [:] }
}

extension String {
  /// an ISO 8601 time from the router (with or without fractional seconds)
  var isoDate: Date? {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = f.date(from: self) { return d }
    f.formatOptions = [.withInternetDateTime]
    return f.date(from: self)
  }
}
