.pragma library

function plain(value, maxLen) {
    var text = value === undefined || value === null ? "" : String(value)
    var limit = maxLen > 0 ? maxLen : 160
    var out = ""
    for (var i = 0; i < text.length && out.length < limit; i++) {
        var code = text.charCodeAt(i)
        if (code < 32 || (code >= 127 && code <= 159))
            continue
        if (code === 0x200E || code === 0x200F || (code >= 0x202A && code <= 0x202E) || (code >= 0x2066 && code <= 0x2069))
            continue
        var ch = text.charAt(i)
        if (ch === "<" || ch === ">" || ch === "&")
            continue
        out += ch
    }
    return out
}
