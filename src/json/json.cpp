#include "tessera/json/json.hpp"

#include <charconv>
#include <cmath>
#include <format>
#include <limits>
#include <new>

#include "tessera/utility/encoding.hpp"

namespace tessera::json {

namespace {

class Parser {
public:
    Parser(std::string_view input, const JsonParseOptions& options, JsonParseError* out_error) noexcept
        : input_(input), options_(options), out_error_(out_error) {}

    [[nodiscard]] Result<JsonValue> run() {
        if (input_.size() > options_.max_bytes) {
            return make_err(JsonErrorCode::MaxSizeExceeded, 0, "JSON input exceeds max_bytes limit");
        }
        if (!encoding::is_valid_utf8(input_)) {
            return make_err(JsonErrorCode::InvalidUtf8, 0, "JSON input is not valid UTF-8");
        }

        skip_whitespace();
        if (pos_ >= input_.size()) {
            return make_err(JsonErrorCode::EmptyInput, pos_, "JSON input is empty");
        }

        auto val = parse_value(0);
        if (!val) {
            return val;
        }

        skip_whitespace();
        if (pos_ < input_.size()) {
            return make_err(JsonErrorCode::TrailingContent,
                            pos_,
                            "Unexpected trailing content after root JSON value");
        }
        return val;
    }

private:
    void skip_whitespace() noexcept {
        while (pos_ < input_.size()) {
            const char c = input_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    [[nodiscard]] std::unexpected<Error> make_err(JsonErrorCode code,
                                                  std::size_t offset,
                                                  std::string_view reason) {
        std::size_t line = 1;
        std::size_t col = 1;
        for (std::size_t i = 0; i < offset && i < input_.size(); ++i) {
            if (input_[i] == '\n') {
                ++line;
                col = 1;
            } else {
                ++col;
            }
        }
        std::string msg = std::format("line {}, column {}: {}", line, col, reason);
        if (out_error_ != nullptr) {
            *out_error_ = JsonParseError{
                .code = code,
                .byte_offset = offset,
                .line = line,
                .column = col,
                .message = msg,
            };
        }
        return fail(ErrorCode::ParseError, "json::parse", 0, std::move(msg));
    }

    [[nodiscard]] Result<JsonValue> parse_value(std::size_t depth) {
        if (depth > options_.max_depth) {
            return make_err(JsonErrorCode::MaxDepthExceeded,
                            pos_,
                            "JSON nesting exceeds max_depth limit");
        }
        skip_whitespace();
        if (pos_ >= input_.size()) {
            return make_err(JsonErrorCode::UnexpectedEndOfInput, pos_, "Unexpected end of JSON input");
        }

        const char c = input_[pos_];
        switch (c) {
            case 'n': return parse_null();
            case 't':
            case 'f': return parse_bool();
            case '"': {
                auto s = parse_string();
                if (!s) {
                    return std::unexpected(s.error());
                }
                return JsonValue{std::move(*s)};
            }
            case '[': return parse_array(depth + 1);
            case '{': return parse_object(depth + 1);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return parse_number();
                }
                return make_err(JsonErrorCode::UnexpectedToken, pos_, "Unexpected character in JSON");
        }
    }

    [[nodiscard]] Result<JsonValue> parse_null() {
        if (input_.substr(pos_, 4) == "null") {
            pos_ += 4;
            return JsonValue{nullptr};
        }
        return make_err(JsonErrorCode::InvalidLiteral, pos_, "Expected 'null'");
    }

    [[nodiscard]] Result<JsonValue> parse_bool() {
        if (input_.substr(pos_, 4) == "true") {
            pos_ += 4;
            return JsonValue{true};
        }
        if (input_.substr(pos_, 5) == "false") {
            pos_ += 5;
            return JsonValue{false};
        }
        return make_err(JsonErrorCode::InvalidLiteral, pos_, "Expected 'true' or 'false'");
    }

    [[nodiscard]] static constexpr bool parse_hex4(std::string_view sv, std::uint16_t& out) noexcept {
        if (sv.size() != 4) {
            return false;
        }
        std::uint16_t val = 0;
        for (const char c : sv) {
            val <<= 4;
            if (c >= '0' && c <= '9') {
                val |= static_cast<std::uint16_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                val |= static_cast<std::uint16_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                val |= static_cast<std::uint16_t>(c - 'A' + 10);
            } else {
                return false;
            }
        }
        out = val;
        return true;
    }

    static void append_utf8_codepoint(std::string& out, char32_t cp) {
        if (cp < 0x80u) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800u) {
            out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp < 0x10000u) {
            out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else {
            out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        }
    }

    [[nodiscard]] Result<std::string> parse_string() {
        const std::size_t start_pos = pos_;
        ++pos_; // skip opening '"'
        std::string out;

        while (pos_ < input_.size()) {
            const char c = input_[pos_];
            if (c == '"') {
                ++pos_;
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20u) {
                return make_err(JsonErrorCode::UnescapedControlCharacter,
                                pos_,
                                "Unescaped control character in JSON string");
            }
            if (c != '\\') {
                out.push_back(c);
                ++pos_;
                continue;
            }

            // Escape sequence
            if (pos_ + 1 >= input_.size()) {
                return make_err(JsonErrorCode::UnterminatedString, start_pos, "Unterminated escape in string");
            }
            const char esc = input_[pos_ + 1];
            pos_ += 2;
            switch (esc) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    if (pos_ + 4 > input_.size()) {
                        return make_err(JsonErrorCode::InvalidStringEscape,
                                        pos_ - 2,
                                        "Incomplete \\uXXXX escape");
                    }
                    std::uint16_t u1 = 0;
                    if (!parse_hex4(input_.substr(pos_, 4), u1)) {
                        return make_err(JsonErrorCode::InvalidStringEscape,
                                        pos_ - 2,
                                        "Invalid hex digits in \\uXXXX escape");
                    }
                    pos_ += 4;
                    char32_t cp = u1;
                    if (u1 >= 0xD800u && u1 <= 0xDBFFu) {
                        // High surrogate must be followed by \uDC00..\uDFFF
                        if (pos_ + 6 > input_.size() || input_[pos_] != '\\' || input_[pos_ + 1] != 'u') {
                            return make_err(JsonErrorCode::InvalidStringEscape,
                                            pos_ - 6,
                                            "Unpaired high surrogate in JSON string");
                        }
                        std::uint16_t u2 = 0;
                        if (!parse_hex4(input_.substr(pos_ + 2, 4), u2) ||
                            u2 < 0xDC00u || u2 > 0xDFFFu) {
                            return make_err(JsonErrorCode::InvalidStringEscape,
                                            pos_,
                                            "Invalid low surrogate in JSON string");
                        }
                        pos_ += 6;
                        cp = 0x10000u + (((static_cast<char32_t>(u1) - 0xD800u) << 10) |
                                         (static_cast<char32_t>(u2) - 0xDC00u));
                    } else if (u1 >= 0xDC00u && u1 <= 0xDFFFu) {
                        return make_err(JsonErrorCode::InvalidStringEscape,
                                        pos_ - 6,
                                        "Unpaired low surrogate in JSON string");
                    }
                    append_utf8_codepoint(out, cp);
                    break;
                }
                default:
                    return make_err(JsonErrorCode::InvalidStringEscape,
                                    pos_ - 2,
                                    "Invalid escape character in JSON string");
            }
        }
        return make_err(JsonErrorCode::UnterminatedString, start_pos, "Unterminated JSON string");
    }

    [[nodiscard]] Result<JsonValue> parse_number() {
        const std::size_t start = pos_;
        bool negative = false;
        if (input_[pos_] == '-') {
            negative = true;
            ++pos_;
            if (pos_ >= input_.size()) {
                return make_err(JsonErrorCode::InvalidNumber, start, "Incomplete negative number");
            }
        }

        // Integer part
        if (input_[pos_] == '0') {
            ++pos_;
            if (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                return make_err(JsonErrorCode::InvalidNumber,
                                start,
                                "Leading zeros are not permitted in JSON numbers (RFC 8259)");
            }
        } else if (input_[pos_] >= '1' && input_[pos_] <= '9') {
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                ++pos_;
            }
        } else {
            return make_err(JsonErrorCode::InvalidNumber, start, "Invalid JSON number");
        }

        bool is_float = false;
        if (pos_ < input_.size() && input_[pos_] == '.') {
            is_float = true;
            ++pos_;
            if (pos_ >= input_.size() || input_[pos_] < '0' || input_[pos_] > '9') {
                return make_err(JsonErrorCode::InvalidNumber,
                                start,
                                "Decimal point must be followed by at least one digit");
            }
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                ++pos_;
            }
        }

        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            is_float = true;
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) {
                ++pos_;
            }
            if (pos_ >= input_.size() || input_[pos_] < '0' || input_[pos_] > '9') {
                return make_err(JsonErrorCode::InvalidNumber,
                                start,
                                "Exponent must contain at least one digit");
            }
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') {
                ++pos_;
            }
        }

        const std::string_view token = input_.substr(start, pos_ - start);
        if (!is_float) {
            if (negative) {
                std::int64_t iv = 0;
                const auto [ptr, ec] =
                    std::from_chars(token.data(), token.data() + token.size(), iv);
                if (ec == std::errc{} && ptr == token.data() + token.size()) {
                    return JsonValue{iv};
                }
                return make_err(JsonErrorCode::NumberOverflow,
                                start,
                                "Signed 64-bit integer overflow");
            } else {
                std::uint64_t uv = 0;
                const auto [ptr, ec] =
                    std::from_chars(token.data(), token.data() + token.size(), uv);
                if (ec == std::errc{} && ptr == token.data() + token.size()) {
                    if (uv <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
                        return JsonValue{static_cast<std::int64_t>(uv)};
                    }
                    return JsonValue{uv};
                }
                return make_err(JsonErrorCode::NumberOverflow,
                                start,
                                "Unsigned 64-bit integer overflow");
            }
        }

        double dv = 0.0;
        const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), dv);
        if (ec != std::errc{} || ptr != token.data() + token.size() || !std::isfinite(dv)) {
            return make_err(JsonErrorCode::NumberOverflow,
                            start,
                            "Floating-point number overflow or invalid representation");
        }
        return JsonValue{dv};
    }

    [[nodiscard]] Result<JsonValue> parse_array(std::size_t depth) {
        if (depth > options_.max_depth) {
            return make_err(JsonErrorCode::MaxDepthExceeded,
                            pos_,
                            "JSON nesting exceeds max_depth limit");
        }
        ++pos_; // skip '['
        skip_whitespace();
        JsonValue::Array arr;
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return JsonValue{std::move(arr)};
        }

        for (;;) {
            auto elem = parse_value(depth);
            if (!elem) {
                return elem;
            }
            arr.push_back(std::move(*elem));

            skip_whitespace();
            if (pos_ >= input_.size()) {
                return make_err(JsonErrorCode::UnexpectedEndOfInput, pos_, "Unterminated JSON array");
            }
            if (input_[pos_] == ']') {
                ++pos_;
                return JsonValue{std::move(arr)};
            }
            if (input_[pos_] != ',') {
                return make_err(JsonErrorCode::UnexpectedToken,
                                pos_,
                                "Expected ',' or ']' in JSON array");
            }
            ++pos_;
            skip_whitespace();
            if (pos_ < input_.size() && input_[pos_] == ']') {
                return make_err(JsonErrorCode::UnexpectedToken,
                                pos_,
                                "Trailing comma is not allowed in JSON array");
            }
        }
    }

    [[nodiscard]] Result<JsonValue> parse_object(std::size_t depth) {
        if (depth > options_.max_depth) {
            return make_err(JsonErrorCode::MaxDepthExceeded,
                            pos_,
                            "JSON nesting exceeds max_depth limit");
        }
        ++pos_; // skip '{'
        skip_whitespace();
        JsonValue::Object obj;
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return JsonValue{std::move(obj)};
        }

        for (;;) {
            skip_whitespace();
            if (pos_ >= input_.size()) {
                return make_err(JsonErrorCode::UnexpectedEndOfInput, pos_, "Unterminated JSON object");
            }
            if (input_[pos_] != '"') {
                return make_err(JsonErrorCode::UnexpectedToken,
                                pos_,
                                "Expected string key in JSON object");
            }
            const std::size_t key_pos = pos_;
            auto key_res = parse_string();
            if (!key_res) {
                return std::unexpected(key_res.error());
            }

            skip_whitespace();
            if (pos_ >= input_.size() || input_[pos_] != ':') {
                return make_err(JsonErrorCode::UnexpectedToken,
                                pos_,
                                "Expected ':' after key in JSON object");
            }
            ++pos_;

            auto val_res = parse_value(depth);
            if (!val_res) {
                return val_res;
            }

            bool found_dup = false;
            for (auto& [existing_k, existing_v] : obj) {
                if (existing_k == *key_res) {
                    found_dup = true;
                    if (options_.duplicate_keys == DuplicateKeyPolicy::Reject) {
                        return make_err(JsonErrorCode::DuplicateKey,
                                        key_pos,
                                        std::format("Duplicate object key '{}'", *key_res));
                    }
                    existing_v = std::move(*val_res);
                    break;
                }
            }
            if (!found_dup) {
                obj.emplace_back(std::move(*key_res), std::move(*val_res));
            }

            skip_whitespace();
            if (pos_ >= input_.size()) {
                return make_err(JsonErrorCode::UnexpectedEndOfInput, pos_, "Unterminated JSON object");
            }
            if (input_[pos_] == '}') {
                ++pos_;
                return JsonValue{std::move(obj)};
            }
            if (input_[pos_] != ',') {
                return make_err(JsonErrorCode::UnexpectedToken,
                                pos_,
                                "Expected ',' or '}' in JSON object");
            }
            ++pos_;
            skip_whitespace();
            if (pos_ < input_.size() && input_[pos_] == '}') {
                return make_err(JsonErrorCode::UnexpectedToken,
                                pos_,
                                "Trailing comma is not allowed in JSON object");
            }
        }
    }

    std::string_view input_;
    const JsonParseOptions& options_;
    JsonParseError* out_error_ = nullptr;
    std::size_t pos_ = 0;
};

void write_escaped_string(std::string& out, std::string_view sv) {
    out.push_back('"');
    for (const char c : sv) {
        const auto uc = static_cast<unsigned char>(c);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (uc < 0x20u) {
                    out += std::format("\\u{:04X}", static_cast<unsigned int>(uc));
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    out.push_back('"');
}

Status write_value_recursive(const JsonValue& val,
                             const JsonWriteOptions& opt,
                             std::size_t depth,
                             std::string& out) {
    const auto indent = [&](std::size_t level) {
        if (opt.pretty) {
            out.append(level * opt.indent_spaces, ' ');
        }
    };

    switch (val.type()) {
        case JsonType::Null:
            out += "null";
            return ok();
        case JsonType::Bool:
            out += (*val.as_bool() ? "true" : "false");
            return ok();
        case JsonType::Int64:
            out += std::format("{}", *val.as_int64());
            return ok();
        case JsonType::UInt64:
            out += std::format("{}", *val.as_uint64());
            return ok();
        case JsonType::Double: {
            const double d = *val.as_double();
            if (!std::isfinite(d)) {
                return fail(ErrorCode::InvalidArgument,
                            "json::write",
                            0,
                            "NaN and Infinity are not valid JSON numbers (RFC 8259)");
            }
            char buf[64]{};
            const auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), d);
            if (ec != std::errc{}) {
                return fail(ErrorCode::InvalidArgument, "json::write");
            }
            out.append(buf, static_cast<std::size_t>(ptr - buf));
            return ok();
        }
        case JsonType::String: {
            const auto sv = *val.as_string();
            if (!encoding::is_valid_utf8(sv)) {
                return fail(ErrorCode::InvalidArgument,
                            "json::write",
                            0,
                            "String value contains invalid UTF-8");
            }
            write_escaped_string(out, sv);
            return ok();
        }
        case JsonType::Array: {
            const auto& arr = *val.as_array();
            if (arr.empty()) {
                out += "[]";
                return ok();
            }
            out.push_back('[');
            if (opt.pretty) {
                out.push_back('\n');
            }
            for (std::size_t i = 0; i < arr.size(); ++i) {
                indent(depth + 1);
                auto st = write_value_recursive(arr[i], opt, depth + 1, out);
                if (!st) {
                    return st;
                }
                if (i + 1 < arr.size()) {
                    out.push_back(',');
                }
                if (opt.pretty) {
                    out.push_back('\n');
                }
            }
            indent(depth);
            out.push_back(']');
            return ok();
        }
        case JsonType::Object: {
            const auto& obj = *val.as_object();
            if (obj.empty()) {
                out += "{}";
                return ok();
            }
            out.push_back('{');
            if (opt.pretty) {
                out.push_back('\n');
            }
            for (std::size_t i = 0; i < obj.size(); ++i) {
                const auto& [k, v] = obj[i];
                if (!encoding::is_valid_utf8(k)) {
                    return fail(ErrorCode::InvalidArgument,
                                "json::write",
                                0,
                                "Object key contains invalid UTF-8");
                }
                indent(depth + 1);
                write_escaped_string(out, k);
                out.push_back(':');
                if (opt.pretty) {
                    out.push_back(' ');
                }
                auto st = write_value_recursive(v, opt, depth + 1, out);
                if (!st) {
                    return st;
                }
                if (i + 1 < obj.size()) {
                    out.push_back(',');
                }
                if (opt.pretty) {
                    out.push_back('\n');
                }
            }
            indent(depth);
            out.push_back('}');
            return ok();
        }
    }
    return fail(ErrorCode::InvalidArgument, "json::write");
}

} // namespace

Result<JsonValue> parse(std::string_view input,
                        const JsonParseOptions& options,
                        JsonParseError* out_error) {
    try {
        Parser p(input, options, out_error);
        return p.run();
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "json::parse");
    }
}

Result<std::string> write(const JsonValue& value, const JsonWriteOptions& options) {
    try {
        std::string out;
        auto st = write_value_recursive(value, options, 0, out);
        if (!st) {
            return std::unexpected(st.error());
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "json::write");
    }
}

} // namespace tessera::json
