import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import "Plain.js" as Plain

Item {
    id: root

    property var shell: null
    property var manifest: null

    property bool scanning: false
    property int doneCount: 0
    property int totalCount: 0
    property int aliveCount: 0
    property bool partial: false
    property string lastError: ""
    property string statusLine: ""
    onStatusLineChanged: {
        if (statusLine === "")
            statusTimer.stop()
        else
            statusTimer.restart()
    }
    property string scannedAt: ""
    property string rangeText: ""
    property bool portChecks: false
    property string portsText: "22, 80, 443, 445, 3389, 9100"
    property bool hideDead: true
    property int maxLatencyMs: 0
    property bool openPortsOnly: false
    property string presetsText: "[]"
    property string columnsText: "hostname,ms,mac,vendor,ports,source"
    property string missingTools: ""
    property string hotkeyState: ""
    property bool hotkeyPending: false
    property bool hotkeyDismissed: false
    property var hosts: []
    property bool windowOpen: false
    property bool loadedOnce: false

    property string phase: ""
    property string scanStdout: ""
    property string scanStderr: ""
    property string scanStdin: ""
    property int scanStdinTries: 0
    property bool scanSawOutput: false
    property string queuedVerb: ""
    property string queuedBody: ""
    property string utilPhase: ""
    property string utilStdout: ""
    property string utilStderr: ""
    property string utilStdin: ""
    property int utilStdinTries: 0
    property bool utilSawOutput: false
    property string utilQueuedVerb: ""
    property string utilQueuedBody: ""
    property bool toolsPending: false
    property bool noted: false
    property bool initialRangeChecked: false
    property string rangeAtDetect: ""

    readonly property string pluginId: "io.github.07dcolem.mellow-ip-scan"

    function filePath(name) {
        var raw = String(Qt.resolvedUrl(name))
        if (raw.indexOf("file://") === 0)
            raw = decodeURIComponent(raw.slice(7))
        return raw
    }

    function helperCommand(verb) {
        return ["/usr/bin/python3", "-I", "-S", filePath("bin/scan.py"), verb]
    }

    function asBool(value) {
        return value === true || value === "true"
    }

    function applyFields(src) {
        var incoming = src || ({})
        // Absent keys keep the current value. An empty settings echo must
        // not turn port checks off or hide-dead back on.
        if (incoming.range !== undefined && incoming.range !== null)
            rangeText = Plain.plain(incoming.range, 64)
        if (incoming.portChecks !== undefined)
            portChecks = asBool(incoming.portChecks)
        if (incoming.ports !== undefined && incoming.ports !== null)
            portsText = Plain.plain(incoming.ports, 64)
        if (incoming.hideDead !== undefined)
            hideDead = incoming.hideDead !== false && incoming.hideDead !== "false"
        if (incoming.maxLatencyMs !== undefined && incoming.maxLatencyMs !== null) {
            var latency = parseInt(incoming.maxLatencyMs, 10)
            maxLatencyMs = isFinite(latency) ? Math.max(0, Math.min(10000, latency)) : 0
        }
        if (incoming.openPortsOnly !== undefined)
            openPortsOnly = asBool(incoming.openPortsOnly)
        if (incoming.presets !== undefined && incoming.presets !== null)
            presetsText = clampPresets(incoming.presets)
        if (incoming.columns !== undefined && incoming.columns !== null)
            columnsText = normalizeColumns(incoming.columns)
        if (incoming.hotkeyDismissed !== undefined)
            hotkeyDismissed = asBool(incoming.hotkeyDismissed)
        noted = true
    }

    function normalizeColumns(value) {
        var known = ["hostname", "ms", "mac", "vendor", "ports", "source"]
        var parts = String(value || "").split(",")
        var out = []
        for (var i = 0; i < parts.length && out.length < known.length; i++) {
            var id = parts[i].replace(/[^a-z]/g, "")
            if (known.indexOf(id) >= 0 && out.indexOf(id) < 0)
                out.push(id)
        }
        for (var j = 0; j < known.length; j++) {
            if (out.indexOf(known[j]) < 0)
                out.push(known[j])
        }
        return out.join(",")
    }

    function acceptTools(value) {
        var known = ["ping", "ip", "hwdata", "nc", "names", "mdns", "copy"]
        var parts = String(value || "").split(",")
        var out = []
        for (var i = 0; i < parts.length && out.length < known.length; i++) {
            var id = parts[i].replace(/[^a-z]/g, "")
            if (known.indexOf(id) >= 0 && out.indexOf(id) < 0)
                out.push(id)
        }
        return out.join(",")
    }

    function acceptHotkey(value) {
        var state = String(value || "")
        if (state === "free" || state === "ours" || state === "taken" || state === "broken")
            return state
        return ""
    }

    function setPanelHotkey() {
        if (hotkeyState !== "free" || hotkeyDismissed)
            return
        run("hotkey-set", "")
    }

    function dismissPanelHotkey() {
        saveSettings({ hotkeyDismissed: true })
    }

    function clampPresets(value) {
        var parsed = []
        try {
            parsed = typeof value === "string" ? JSON.parse(value || "[]") : value
        } catch (error) {
            parsed = []
        }
        if (!Array.isArray(parsed))
            return "[]"
        var kept = []
        for (var i = 0; i < parsed.length && kept.length < 8; i++) {
            var row = parsed[i]
            if (!row)
                continue
            var name = Plain.plain(row.name || "", 32)
            var range = Plain.plain(row.range || "", 64)
            if (!name || !range || name.indexOf("..") >= 0)
                continue
            kept.push({ name: name, range: range })
        }
        return JSON.stringify(kept)
    }

    function snapshot() {
        return {
            range: rangeText,
            portChecks: portChecks,
            ports: portsText,
            hideDead: hideDead,
            maxLatencyMs: maxLatencyMs,
            openPortsOnly: openPortsOnly,
            presets: presetsText,
            columns: columnsText,
            hotkeyDismissed: hotkeyDismissed
        }
    }

    function noteSettings(raw) {
        if (!raw)
            return
        applyFields(raw)
        considerInitialRange()
    }

    function considerInitialRange() {
        if (initialRangeChecked)
            return
        initialRangeChecked = true
        if (rangeText === "")
            redetect()
    }

    function layoutEntry(id) {
        var config = shell && shell.barConfig
        var layout = config && config.layout
        if (!layout)
            return null
        var sections = ["left", "centerBegin", "center", "centerEnd", "right", "tray"]
        for (var s = 0; s < sections.length; s++) {
            var rows = layout[sections[s]] || []
            for (var i = 0; i < rows.length; i++) {
                if (rows[i] && rows[i].id === id)
                    return rows[i]
            }
        }
        return null
    }

    function settingsFromBar() {
        return layoutEntry(pluginId)
    }

    // The bar clock stores the pattern the user is looking at. The scan
    // time uses that pattern and keeps this panel's own type.
    function clockFormat() {
        var entry = layoutEntry("omarchy.clock")
        var format = Plain.plain(entry && entry.format ? entry.format : "", 80)
        return format !== "" ? format : "dddd HH:mm"
    }

    function saveSettings(patch) {
        var merged = snapshot()
        var incoming = patch || ({})
        var keys = ["range", "portChecks", "ports", "hideDead", "maxLatencyMs", "openPortsOnly", "presets", "columns", "hotkeyDismissed"]
        for (var i = 0; i < keys.length; i++) {
            if (incoming[keys[i]] !== undefined)
                merged[keys[i]] = incoming[keys[i]]
        }
        applyFields(merged)
        if (shell && shell.updateEntryInline)
            shell.updateEntryInline(pluginId, snapshot())
    }

    function ensureNoted() {
        if (noted)
            return
        var stored = settingsFromBar()
        if (stored)
            applyFields(stored)
        else
            noted = true
    }

    function takeHost(row) {
        if (!row || typeof row.ip !== "string")
            return null
        var ip = Plain.plain(row.ip, 15)
        if (!/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(ip))
            return null
        var ports = []
        var sourcePorts = row.ports || []
        for (var i = 0; i < sourcePorts.length && ports.length < 8; i++) {
            var port = parseInt(sourcePorts[i], 10)
            if (port >= 1 && port <= 65535)
                ports.push(port)
        }
        var ms = row.ms === null || row.ms === undefined ? null : parseInt(row.ms, 10)
        if (ms !== null && (!isFinite(ms) || ms < 0 || ms > 10000))
            ms = null
        var source = row.hostnameSource === "dns" || row.hostnameSource === "mdns" ? row.hostnameSource : ""
        return {
            ip: ip,
            alive: row.alive === true,
            ms: row.alive === true ? (ms === null ? 0 : ms) : null,
            mac: Plain.plain(row.mac || "", 17),
            vendor: Plain.plain(row.vendor || "", 64),
            hostname: Plain.plain(row.hostname || "", 253),
            hostnameSource: source,
            ports: ports
        }
    }

    function upsert(host) {
        var next = hosts.slice()
        var found = -1
        for (var i = 0; i < next.length; i++) {
            if (next[i].ip === host.ip)
                found = i
        }
        if (found >= 0)
            next[found] = host
        else if (next.length < 1024)
            next.push(host)
        hosts = next
        var alive = 0
        for (var j = 0; j < next.length; j++) {
            if (next[j].alive)
                alive++
        }
        aliveCount = alive
    }

    function applyLine(line, fromScan) {
        var row = null
        try {
            row = JSON.parse(line)
        } catch (error) {
            return
        }
        if (!row || !row.t)
            return
        if (!fromScan && scanning && (row.t === "meta" || row.t === "host" || row.t === "end" || row.t === "state"))
            return
        if (row.t === "error") {
            var message = Plain.plain(row.error || "scan failed", 160)
            if (fromScan) {
                lastError = message
                scanning = false
            } else {
                statusLine = message
            }
            return
        }
        if (row.t === "progress") {
            doneCount = parseInt(row.done, 10) || 0
            totalCount = parseInt(row.total, 10) || totalCount
            return
        }
        if (row.t === "host") {
            var host = takeHost(row)
            if (host)
                upsert(host)
            return
        }
        if (row.t === "meta") {
            hosts = []
            aliveCount = 0
            scannedAt = Plain.plain(row.scannedAt || "", 20)
            totalCount = parseInt(row.total, 10) || 0
            doneCount = parseInt(row.done, 10) || 0
            partial = row.partial === true
            return
        }
        if (row.t === "state" && row.scan === null) {
            loadedOnce = true
            return
        }
        if (row.t === "end") {
            loadedOnce = true
            return
        }
        if (row.t === "done") {
            if (!fromScan)
                return
            scanning = false
            scannedAt = Plain.plain(row.scannedAt || scannedAt, 20)
            doneCount = parseInt(row.done, 10) || doneCount
            totalCount = parseInt(row.total, 10) || totalCount
            partial = row.partial === true
            if (row.note === "port checks need nc")
                statusLine = "nc"
            else if (row.note)
                statusLine = Plain.plain(row.note, 160)
            loadedOnce = true
            return
        }
        if (row.t === "detect") {
            var found = Plain.plain(row.range || "", 64)
            // Ignore a late answer when the user already chose a different range.
            if (found && rangeText === rangeAtDetect)
                saveSettings({ range: found })
            statusLine = ""
            return
        }
        if (row.t === "export") {
            statusLine = "export:" + Plain.plain(row.csv || "", 80)
            return
        }
        if (row.t === "copied") {
            statusLine = "copied"
            return
        }
        if (row.t === "wol") {
            statusLine = "wol"
            return
        }
        if (row.t === "tools") {
            missingTools = acceptTools(row.missing || "")
            return
        }
        if (row.t === "hotkey") {
            var hotkey = acceptHotkey(row.state || "")
            if (hotkey !== "")
                hotkeyState = hotkey
            if (row.wrote === true)
                statusLine = "hotkey-set"
            return
        }
    }

    function consume(chunk, fromScan) {
        var incoming = String(chunk || "")
        if (fromScan) {
            scanSawOutput = true
            scanStdout += incoming
        } else {
            utilSawOutput = true
            utilStdout += incoming
        }
        var buf = fromScan ? scanStdout : utilStdout
        var nl = buf.indexOf("\n")
        if (nl < 0 && buf.length > 8192) {
            if (fromScan)
                scanStdout = ""
            else
                utilStdout = ""
            abortReader(fromScan)
            return
        }
        while (nl >= 0) {
            var line = buf.slice(0, nl)
            buf = buf.slice(nl + 1)
            if (line.length > 1024) {
                if (fromScan)
                    scanStdout = ""
                else
                    utilStdout = ""
                abortReader(fromScan)
                return
            }
            if (line.length > 0)
                applyLine(line, fromScan)
            nl = buf.indexOf("\n")
            if (nl < 0 && buf.length > 8192) {
                buf = ""
                if (fromScan)
                    scanStdout = ""
                else
                    utilStdout = ""
                abortReader(fromScan)
                return
            }
        }
        if (fromScan)
            scanStdout = buf
        else
            utilStdout = buf
    }

    function consumeErr(chunk, fromScan) {
        if (fromScan) {
            scanStderr += String(chunk || "")
            if (scanStderr.length > 4096)
                scanStderr = scanStderr.slice(scanStderr.length - 4096)
        } else {
            utilStderr += String(chunk || "")
            if (utilStderr.length > 4096)
                utilStderr = utilStderr.slice(utilStderr.length - 4096)
        }
    }

    function abortReader(fromScan) {
        if (fromScan) {
            lastError = "scan output exceeded limit"
            if (scanProc.running)
                scanProc.signal(15)
            scanKillTimer.start()
        } else {
            statusLine = "scan output exceeded limit"
            if (utilProc.running)
                utilProc.signal(15)
            utilKillTimer.start()
        }
    }

    function launchScan(body) {
        phase = "scan"
        scanning = true
        hosts = []
        aliveCount = 0
        doneCount = 0
        totalCount = 0
        partial = false
        lastError = ""
        statusLine = ""
        scanStdin = body
        scanStdout = ""
        scanStderr = ""
        scanSawOutput = false
        scanStdinTries = 0
        scanProc.command = helperCommand("scan")
        scanProc.running = true
        if (body !== "")
            stdinTimer.restart()
    }

    function launchUtil(verb, body) {
        utilPhase = verb
        utilStdin = body
        utilStdout = ""
        utilStderr = ""
        utilSawOutput = false
        utilStdinTries = 0
        utilProc.command = helperCommand(verb)
        utilProc.running = true
        if (body !== "")
            stdinTimer.restart()
    }

    function run(verb, body) {
        var line = body === "" ? "" : (body + "\n")
        if (verb === "scan") {
            if (scanProc.running) {
                queuedVerb = verb
                queuedBody = line
                scanProc.signal(15)
                scanKillTimer.start()
                return
            }
            launchScan(line)
            return
        }
        // Copy, export, wake, detect, and state stay off the scan process
        // so they cannot cancel a ping that is already running. The tool
        // check and the hotkey read wait their turn instead of replacing
        // a queued command. Setting the hotkey is a click, so it may queue.
        if (verb === "tools")
            toolsPending = true
        else if (verb === "hotkey-status")
            hotkeyPending = true
        if (utilProc.running) {
            if (verb !== "tools" && verb !== "hotkey-status") {
                utilQueuedVerb = verb
                utilQueuedBody = line
            }
            return
        }
        if (verb === "tools")
            toolsPending = false
        else if (verb === "hotkey-status")
            hotkeyPending = false
        launchUtil(verb, line)
    }

    function start() {
        ensureNoted()
        if (!rangeText) {
            lastError = "need-range"
            return
        }
        run("scan", JSON.stringify({
            range: rangeText,
            ports: portsText,
            portChecks: portChecks === true
        }))
    }

    function stop() {
        queuedVerb = ""
        queuedBody = ""
        if (!scanProc.running) {
            scanning = false
            return
        }
        scanProc.signal(15)
        scanKillTimer.start()
    }

    function redetect() {
        rangeAtDetect = rangeText
        run("detect", "")
    }

    function toggleWindow() {
        windowOpen = !windowOpen
    }

    function openWindow() {
        windowOpen = true
        popout.minimized = false
        try {
            popout.requestActivate()
        } catch (error) {
        }
    }

    function copyText(text) {
        var clean = Plain.plain(text, 512)
        if (!clean) {
            statusLine = "copy-fail"
            return
        }
        run("copy", JSON.stringify({ text: clean }))
    }

    function exportHosts(list) {
        var rows = []
        var source = list || []
        for (var i = 0; i < source.length && rows.length < 1024; i++) {
            var host = takeHost(source[i])
            if (host)
                rows.push(host)
        }
        var now = new Date()
        function pad(value) { return (value < 10 ? "0" : "") + value }
        var stamp = "" + now.getFullYear() + pad(now.getMonth() + 1) + pad(now.getDate())
            + "-" + pad(now.getHours()) + pad(now.getMinutes()) + pad(now.getSeconds())
        run("export", JSON.stringify({ hosts: rows, stamp: stamp }))
    }

    function wake(mac) {
        ensureNoted()
        run("wol", JSON.stringify({ mac: Plain.plain(mac, 17), range: rangeText }))
    }

    function status() {
        return JSON.stringify({
            scanning: scanning,
            done: doneCount,
            total: totalCount,
            alive: aliveCount,
            error: Plain.plain(lastError, 160)
        })
    }

    Process {
        id: scanProc
        command: ["/usr/bin/true"]
        // The helper scrubs its own environment. clearEnvironment on this
        // Quickshell build drops the stdin write, so the request never arrives.
        clearEnvironment: false
        environment: ({ PATH: "/usr/bin", LC_ALL: "C" })
        workingDirectory: "/usr"
        stdinEnabled: true
        stdout: SplitParser {
            splitMarker: ""
            onRead: function(chunk) { root.consume(chunk, true) }
        }
        stderr: SplitParser {
            splitMarker: ""
            onRead: function(chunk) { root.consumeErr(chunk, true) }
        }
        onStarted: {
            if (root.scanStdin !== "")
                write(root.scanStdin)
        }
        onExited: function(code) {
            scanKillTimer.stop()
            root.scanning = false
            if (code !== 0 && root.lastError === "" && root.scanStderr !== "")
                root.lastError = Plain.plain(root.scanStderr, 160)
            var verb = root.queuedVerb
            var body = root.queuedBody
            root.queuedVerb = ""
            root.queuedBody = ""
            if (verb === "scan")
                root.launchScan(body)
        }
    }

    Process {
        id: utilProc
        command: ["/usr/bin/true"]
        clearEnvironment: false
        environment: ({ PATH: "/usr/bin", LC_ALL: "C" })
        workingDirectory: "/usr"
        stdinEnabled: true
        stdout: SplitParser {
            splitMarker: ""
            onRead: function(chunk) { root.consume(chunk, false) }
        }
        stderr: SplitParser {
            splitMarker: ""
            onRead: function(chunk) { root.consumeErr(chunk, false) }
        }
        onStarted: {
            if (root.utilStdin !== "")
                write(root.utilStdin)
        }
        onExited: function(code) {
            utilKillTimer.stop()
            if (code !== 0 && root.utilStderr !== "" && root.statusLine === "")
                root.statusLine = Plain.plain(root.utilStderr, 160)
            var verb = root.utilQueuedVerb
            var body = root.utilQueuedBody
            root.utilQueuedVerb = ""
            root.utilQueuedBody = ""
            if (verb !== "")
                root.launchUtil(verb, body)
            else if (root.toolsPending) {
                root.toolsPending = false
                root.launchUtil("tools", "")
            } else if (root.hotkeyPending) {
                root.hotkeyPending = false
                root.launchUtil("hotkey-status", "")
            }
        }
    }

    Timer {
        id: statusTimer
        interval: 2500
        onTriggered: root.statusLine = ""
    }

    Timer {
        id: stdinTimer
        interval: 100
        repeat: true
        onTriggered: {
            var scanNeeds = scanProc.running && root.scanStdin !== "" && !root.scanSawOutput && root.scanStdin.length <= 4096 && root.scanStdinTries < 3
            var utilNeeds = utilProc.running && root.utilStdin !== "" && !root.utilSawOutput && root.utilStdin.length <= 4096 && root.utilStdinTries < 3
            if (scanNeeds) {
                root.scanStdinTries++
                scanProc.write(root.scanStdin)
            }
            if (utilNeeds) {
                root.utilStdinTries++
                utilProc.write(root.utilStdin)
            }
            if (!scanNeeds && !utilNeeds)
                stdinTimer.stop()
        }
    }

    Timer {
        id: scanKillTimer
        interval: 5000
        onTriggered: if (scanProc.running) scanProc.signal(9)
    }

    Timer {
        id: utilKillTimer
        interval: 5000
        onTriggered: if (utilProc.running) utilProc.signal(9)
    }

    Timer {
        id: scanDeadline
        interval: 180000
        repeat: false
        running: root.scanning
        onTriggered: root.stop()
    }

    IpcHandler {
        target: "io.github.07dcolem.mellow-ip-scan"
        function start(): void { root.start() }
        function stop(): void { root.stop() }
        function status(): string { return root.status() }
        function toggleWindow(): void { root.toggleWindow() }
    }

    FloatingWindow {
        id: popout
        title: "Mellow IP Scan"
        visible: root.windowOpen
        color: Commons.Color.popups.background
        implicitWidth: 560
        implicitHeight: 560
        minimumSize: Qt.size(520, 320)
        onVisibleChanged: {
            if (!visible && root.windowOpen)
                root.windowOpen = false
        }

        ScanView {
            id: windowView
            anchors.fill: parent
            anchors.margins: Style.space(12)
            service: root
            showWindowButton: false
            onCloseRequested: root.windowOpen = false
        }
        Connections {
            target: popout
            function onVisibleChanged() {
                if (popout.visible)
                    windowView.forceActiveFocus()
            }
        }
    }

    Timer {
        id: initialRangeTimer
        interval: 600
        repeat: false
        running: true
        onTriggered: {
            if (root.initialRangeChecked)
                return
            var stored = root.settingsFromBar()
            if (stored)
                root.applyFields(stored)
            root.considerInitialRange()
        }
    }

    Component.onCompleted: {
        root.run("read-state", "")
        root.run("tools", "")
        root.run("hotkey-status", "")
    }
    Component.onDestruction: {
        root.stop()
        if (utilProc.running)
            utilProc.signal(15)
    }
}
