import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Plain.js" as Plain

FocusScope {
    id: root

    property var service: null
    property bool showWindowButton: true
    readonly property bool hotkeyOfferVisible: showWindowButton && service && service.noted && service.hotkeyState === "free" && !service.hotkeyDismissed
    // Options keeps the set button while the chord is free. Nothing on that
    // page hides it, in the dropdown or the window.
    readonly property bool optionsHotkeyVisible: service && service.noted && service.hotkeyState === "free"
    property string page: "list"
    property bool optionCursorUsed: false
    onPageChanged: {
        optionCursorUsed = false
        if (service)
            service.statusLine = ""
    }
    property int cursor: 0
    property string query: ""
    property string focusedIp: ""
    property bool followIp: false
    signal closeRequested()

    implicitWidth: Style.space(400)
    implicitHeight: column.implicitHeight

    readonly property bool editing: queryLine.editing || latencyLine.editing || rangeLine.editing || portsLine.editing || presetLine.editing
    readonly property var presets: {
        var parsed = []
        try {
            parsed = JSON.parse(service && service.presetsText ? service.presetsText : "[]")
        } catch (error) {
            parsed = []
        }
        return Array.isArray(parsed) ? parsed : []
    }
    readonly property var rows: {
        var source = service ? service.hosts : []
        var out = []
        var needle = query.toLowerCase()
        for (var i = 0; i < source.length; i++) {
            var host = source[i]
            if (!host)
                continue
            if (service.hideDead && !host.alive)
                continue
            if (service.openPortsOnly && (!host.ports || host.ports.length === 0))
                continue
            if (service.maxLatencyMs > 0 && (!host.alive || host.ms === null || host.ms > service.maxLatencyMs))
                continue
            if (needle !== "") {
                var blob = (host.ip + " " + host.hostname + " " + host.mac + " " + host.vendor).toLowerCase()
                if (blob.indexOf(needle) < 0)
                    continue
            }
            out.push(host)
        }
        out.sort(function(a, b) {
            var left = String(a.ip || "").split(".")
            var right = String(b.ip || "").split(".")
            for (var part = 0; part < 4; part++) {
                var delta = (parseInt(left[part], 10) || 0) - (parseInt(right[part], 10) || 0)
                if (delta !== 0)
                    return delta
            }
            return 0
        })
        return out
    }
    readonly property var focused: cursor >= 0 && cursor < rows.length ? rows[cursor] : null

    onRowsChanged: {
        if (page !== "list")
            return
        if (followIp && focusedIp !== "") {
            for (var i = 0; i < rows.length; i++) {
                if (rows[i].ip === focusedIp) {
                    cursor = i
                    return
                }
            }
        }
        if (cursor >= rows.length)
            cursor = Math.max(0, rows.length - 1)
    }

    function move(delta) {
        var count = page === "list" ? rows.length : (page === "filters" ? 4 : presetBase + presets.length)
        if (count < 1)
            return
        cursor = (cursor + delta + count) % count
        if (page === "options")
            optionCursorUsed = true
        if (page === "list") {
            followIp = true
            if (rows[cursor])
                focusedIp = rows[cursor].ip
            ensureVisible()
        }
    }

    function ensureVisible() {
        var y = cursor * rowHeight
        if (y < hostList.contentY)
            hostList.contentY = y
        else if (y + rowHeight > hostList.contentY + hostList.height)
            hostList.contentY = y + rowHeight - hostList.height
    }

    // The list cursor is the host on screen. Other pages keep the host you
    // left, so copy and wake do not treat a filter row as a host index.
    function rememberedHost() {
        if (page === "list")
            return cursor >= 0 && cursor < rows.length ? rows[cursor] : null
        if (focusedIp === "")
            return null
        for (var i = 0; i < rows.length; i++) {
            if (rows[i] && rows[i].ip === focusedIp)
                return rows[i]
        }
        return null
    }

    function rememberListHost() {
        if (page !== "list")
            return
        if (cursor >= 0 && cursor < rows.length && rows[cursor] && rows[cursor].ip) {
            focusedIp = rows[cursor].ip
            followIp = true
        }
    }

    function backToList() {
        page = "list"
        cursor = 0
        if (followIp && focusedIp !== "") {
            for (var i = 0; i < rows.length; i++) {
                if (rows[i].ip === focusedIp) {
                    cursor = i
                    break
                }
            }
        }
    }

    function openFilters() {
        rememberListHost()
        page = "filters"
        cursor = 0
    }

    function openOptions() {
        rememberListHost()
        page = "options"
        cursor = 0
    }

    function focusedText(kind) {
        var host = rememberedHost()
        if (!host)
            return ""
        if (kind === "ip")
            return host.ip
        if (kind === "mac")
            return host.mac
        return host.hostname
    }

    function isoWeekToken(date) {
        var utc = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()))
        var weekday = utc.getUTCDay() || 7
        utc.setUTCDate(utc.getUTCDate() + 4 - weekday)
        var yearStart = new Date(Date.UTC(utc.getUTCFullYear(), 0, 1))
        var week = Math.ceil((((utc - yearStart) / 86400000) + 1) / 7)
        var text = (week < 10 ? "0" : "") + week
        return text.split("").map(function (digit) {
            return Commons.I18n.formatNumber(digit)
        }).join("")
    }

    function whenLabel() {
        if (!service || !service.scannedAt)
            return strings.t("scan.none")
        var date = new Date(service.scannedAt)
        if (isNaN(date.getTime()))
            return strings.t("scan.none")
        var localeName = Commons.I18n && Commons.I18n.formatLocale ? Commons.I18n.formatLocale : "en"
        var format = service.clockFormat ? service.clockFormat() : "dddd HH:mm"
        var rendered = date.toLocaleString(Qt.locale(localeName), format.replace(/ww/g, isoWeekToken(date)))
        return strings.t(service.partial ? "scan.partial" : "scan.last").arg(rendered)
    }

    function progressLabel() {
        if (!service)
            return strings.t("scan.unavailable")
        if (service.scanning)
            return strings.t("scan.progress").arg(Commons.I18n.formatNumber(service.doneCount, 0)).arg(Commons.I18n.formatNumber(service.totalCount, 0))
        return whenLabel()
    }

    function statusLabel() {
        if (!service)
            return strings.t("scan.unavailable")
        if (service.lastError === "need-range")
            return strings.t("scan.needRange")
        if (service.lastError === "copy" || service.statusLine === "copy-fail")
            return strings.t("copy.fail")
        if (service.statusLine === "copied")
            return strings.t("copy.ok")
        if (service.statusLine === "wol")
            return strings.t("wol.ok")
        if (service.statusLine === "saved")
            return strings.t("options.saved")
        if (service.statusLine === "removed")
            return strings.t("options.removed")
        if (service.statusLine === "full")
            return strings.t("options.full")
        if (service.statusLine === "nc")
            return strings.t("scan.nc")
        if (service.statusLine === "hotkey-set")
            return strings.t("hotkey.set")
        if (service.statusLine.indexOf("export:") === 0)
            return strings.t("export.wrote").arg(Plain.plain(service.statusLine.slice(7), 80))
        if (service.statusLine)
            return Plain.plain(service.statusLine, 160)
        if (service.lastError)
            return Plain.plain(service.lastError, 160)
        return ""
    }

    function savePreset() {
        if (!service)
            return
        var name = Plain.plain(presetLine.text, 32)
        var range = Plain.plain(service.rangeText, 64)
        if (!name || !range)
            return
        var next = []
        var replaced = false
        for (var i = 0; i < presets.length; i++) {
            if (presets[i] && presets[i].name === name) {
                next.push({ name: name, range: range })
                replaced = true
            } else if (presets[i]) {
                next.push(presets[i])
            }
        }
        if (!replaced) {
            if (next.length >= 8) {
                service.statusLine = "full"
                return
            }
            next.push({ name: name, range: range })
        }
        service.saveSettings({ presets: JSON.stringify(next) })
        service.statusLine = "saved"
        presetLine.text = ""
    }

    function focusKeys() {
        catcher.forceActiveFocus()
    }

    function quietOthers(active) {
        var lines = [queryLine, latencyLine, rangeLine, portsLine, presetLine]
        for (var i = 0; i < lines.length; i++) {
            if (lines[i] !== active && lines[i].editing)
                lines[i].abandon()
        }
    }

    function launchWindow() {
        if (!service)
            return
        service.openWindow()
        closeRequested()
    }

    function selectHost(index) {
        if (index < 0 || index >= rows.length)
            return
        cursor = index
        followIp = true
        focusedIp = rows[index].ip
        ensureVisible()
    }

    function deletePreset() {
        if (!service || page !== "options")
            return
        if (cursor >= columnBase && cursor < columnBase + columnSlots) {
            moveColumn(cursor - columnBase, 1)
            return
        }
        if (cursor < presetBase)
            return
        var index = cursor - presetBase
        if (!presets[index])
            return
        var next = presets.slice()
        next.splice(index, 1)
        service.saveSettings({ presets: JSON.stringify(next) })
        service.statusLine = "removed"
        if (cursor > presetBase - 1 + next.length)
            cursor = presetBase - 1 + next.length
    }

    // A tiled column can stay near 466px, which is too narrow for the roomy
    // button padding. Shrink the padding before the row wraps.
    readonly property int actionPad: {
        var room = listPage.width
        if (room >= Style.space(500))
            return Style.space(8)
        if (room >= Style.space(430))
            return Style.space(4)
        return Style.space(2)
    }
    readonly property int actionGap: actionPad >= Style.space(8) ? Style.space(6) : actionPad
    readonly property int rowHeight: Style.space(28)

    FontMetrics {
        id: bodyMetrics
        font.family: Style.font.family
        font.pixelSize: Style.font.body
    }

    FontMetrics {
        id: captionMetrics
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
    }

    // QML FontMetrics exposes advanceWidth, not QFontMetrics.horizontalAdvance.
    // A missing measurement falls back to a width that still fits the sample.
    function measuredWidth(advance, floor) {
        if (!(advance > 0))
            return floor
        return Math.max(floor, Math.ceil(advance) + Style.space(2))
    }

    readonly property int ipWidth: measuredWidth(bodyMetrics.advanceWidth("> 255.255.255.255"), Style.space(136))
    readonly property int macWidth: measuredWidth(bodyMetrics.advanceWidth("00:00:5e:00:00:01"), Style.space(136))
    readonly property int latencyWidth: measuredWidth(bodyMetrics.advanceWidth("10000 ms"), Style.space(72))
    readonly property int columnBase: 4
    readonly property int columnSlots: 6
    readonly property int presetField: 10
    readonly property int saveSlot: 11
    readonly property int presetBase: 12
    readonly property var columnIds: {
        var text = service && service.columnsText ? service.columnsText : "hostname,ms,mac,vendor,ports,source"
        var parts = String(text).split(",")
        var out = []
        for (var i = 0; i < parts.length; i++) {
            if (parts[i])
                out.push(parts[i])
        }
        return out
    }
    readonly property bool portsHaveValues: {
        for (var i = 0; i < rows.length; i++) {
            var host = rows[i]
            if (host && host.ports && host.ports.length)
                return true
        }
        return false
    }
    // Width of each column's longest value in this list, plus its header.
    // An empty Ports column stops at the header. Independent of the window width.
    readonly property var measuredColumns: {
        var widths = []
        var order = columnIds
        var source = rows
        for (var c = 0; c < order.length; c++) {
            var id = order[c]
            var width = measuredWidth(captionMetrics.advanceWidth(columnLabel(id)), Style.space(16))
            if (id === "mac")
                width = Math.max(width, macWidth)
            if (!(id === "ports" && !portsHaveValues)) {
                for (var i = 0; i < source.length; i++) {
                    var host = source[i]
                    if (!host)
                        continue
                    if (id === "ports" && !(host.ports && host.ports.length))
                        continue
                    var textWidth = measuredWidth(bodyMetrics.advanceWidth(cellText(host, id)), 0)
                    if (textWidth > width)
                        width = textWidth
                }
                if (id === "hostname" || id === "vendor")
                    width = Math.max(width, columnMin(id))
            }
            widths.push({ id: id, width: width })
        }
        return widths
    }

    function measuredFor(id) {
        var measured = measuredColumns
        for (var i = 0; i < measured.length; i++) {
            if (measured[i].id === id)
                return measured[i].width
        }
        return 0
    }
    readonly property var shownColumns: packColumns(listFrame.width)

    function columnMin(id) {
        if (id === "hostname")
            return Style.space(72)
        if (id === "ms")
            return latencyWidth
        if (id === "mac")
            return macWidth
        if (id === "vendor")
            return Style.space(96)
        if (id === "ports")
            return Style.space(88)
        if (id === "source")
            return Style.space(64)
        return 0
    }

    function columnFlex(id) {
        return id === "hostname" || id === "vendor" || id === "ports"
    }

    function columnMax(id) {
        if (id === "hostname")
            return Style.space(320)
        if (id === "vendor")
            return Style.space(240)
        if (id === "ports")
            return Style.space(160)
        return columnMin(id)
    }

    function columnFloor(id) {
        return measuredWidth(captionMetrics.advanceWidth(columnLabel(id)), Style.space(16))
    }

    function columnShares(id) {
        return id === "hostname" || id === "vendor" || (id === "ports" && portsHaveValues)
    }

    function packColumns(outer) {
        if (root.showWindowButton)
            return packDropdownColumns(outer)
        return packWindowColumns(outer)
    }

    // The dropdown keeps a column only when its minimum fits, then grows
    // name, vendor, and ports up to a cap. Later columns stay hidden.
    function packDropdownColumns(outer) {
        var gap = Style.space(8)
        var inner = Math.max(0, outer - hostList.barGap - Style.space(12))
        var used = ipWidth
        var chosen = []
        var order = columnIds
        for (var i = 0; i < order.length; i++) {
            var min = columnMin(order[i])
            if (!(min > 0 && used + gap + min <= inner + 0.5))
                break
            chosen.push(order[i])
            used += gap + min
        }
        var extra = Math.max(0, inner - used)
        var widths = []
        for (var k = 0; k < chosen.length; k++)
            widths.push(columnMin(chosen[k]))
        for (var j = 0; j < chosen.length && extra > 0; j++) {
            if (!columnFlex(chosen[j]))
                continue
            var room = Math.max(0, columnMax(chosen[j]) - widths[j])
            var add = Math.min(extra, room)
            widths[j] += add
            extra -= add
        }
        var out = []
        for (var n = 0; n < chosen.length; n++)
            out.push({ id: chosen[n], width: widths[n] })
        return out
    }

    // The window sizes latency, MAC, and source to a full value. Name, vendor,
    // and ports (once a host has a port) grow to the longest value, then share
    // whatever width is left. An empty Ports column stays on its header.
    function packWindowColumns(outer) {
        var gap = Style.space(8)
        var inner = Math.max(0, outer - hostList.barGap - Style.space(12))
        var order = columnIds.slice()
        while (order.length > 0) {
            var widths = []
            var used = ipWidth
            for (var i = 0; i < order.length; i++) {
                var pref = measuredFor(order[i])
                widths.push(pref > 0 ? pref : columnMin(order[i]))
                used += gap + widths[i]
            }
            var extra = inner - used
            if (extra >= 0) {
                var flex = []
                for (var j = 0; j < order.length; j++) {
                    if (columnShares(order[j]))
                        flex.push(j)
                }
                if (flex.length > 0 && extra > 0) {
                    var share = Math.floor(extra / flex.length)
                    var rest = extra - share * flex.length
                    for (var f = 0; f < flex.length; f++)
                        widths[flex[f]] += share + (f === flex.length - 1 ? rest : 0)
                }
                var fitted = []
                for (var n = 0; n < order.length; n++)
                    fitted.push({ id: order[n], width: widths[n] })
                return fitted
            }
            var need = -extra
            var slack = 0
            var flexIdx = []
            for (var k = 0; k < order.length; k++) {
                if (!columnShares(order[k]))
                    continue
                flexIdx.push(k)
                slack += Math.max(0, widths[k] - columnFloor(order[k]))
            }
            if (slack >= need && flexIdx.length > 0) {
                var removed = 0
                for (var t = 0; t < flexIdx.length; t++) {
                    var idx = flexIdx[t]
                    var room = Math.max(0, widths[idx] - columnFloor(order[idx]))
                    var cut = t === flexIdx.length - 1 ? need - removed : Math.floor(need * room / slack)
                    cut = Math.max(0, Math.min(cut, room, need - removed))
                    widths[idx] -= cut
                    removed += cut
                }
                var squeezed = []
                for (var s = 0; s < order.length; s++)
                    squeezed.push({ id: order[s], width: widths[s] })
                return squeezed
            }
            order.pop()
        }
        return []
    }

    function columnShown(id) {
        for (var i = 0; i < shownColumns.length; i++) {
            if (shownColumns[i].id === id)
                return true
        }
        return false
    }

    function columnLabel(id) {
        if (id === "hostname" || id === "ms" || id === "mac" || id === "vendor" || id === "ports" || id === "source")
            return strings.t("columns." + id)
        return ""
    }

    function cellText(host, id) {
        if (!host)
            return strings.t("row.unresolved")
        if (id === "hostname")
            return host.hostname ? Plain.plain(host.hostname, 253) : strings.t("row.unresolved")
        if (id === "ms") {
            if (!host.alive || host.ms === null)
                return strings.t("row.unresolved")
            return host.ms < 1 ? "<1 ms" : Commons.I18n.formatNumber(host.ms, 0) + " ms"
        }
        if (id === "mac")
            return host.mac ? Plain.plain(host.mac, 17) : strings.t("row.unresolved")
        if (id === "vendor")
            return host.vendor ? Plain.plain(host.vendor, 64) : strings.t("row.unresolved")
        if (id === "ports") {
            var ports = host.ports || []
            if (!ports.length)
                return strings.t("row.unresolved")
            var joined = ""
            for (var i = 0; i < ports.length; i++)
                joined += (i ? " " : "") + String(ports[i])
            return Plain.plain(joined, 64)
        }
        if (id === "source") {
            if (host.hostnameSource === "dns")
                return strings.t("columns.dns")
            if (host.hostnameSource === "mdns")
                return strings.t("columns.mdns")
            return strings.t("row.unresolved")
        }
        return ""
    }

    function moveColumn(index, delta) {
        if (!service)
            return
        var order = columnIds.slice()
        var next = index + delta
        if (index < 0 || index >= order.length || next < 0 || next >= order.length)
            return
        var swap = order[index]
        order[index] = order[next]
        order[next] = swap
        service.saveSettings({ columns: order.join(",") })
        cursor = columnBase + next
    }

    function toolWarning() {
        if (!service || !service.missingTools)
            return ""
        var have = String(service.missingTools).split(",")
        var parts = []
        for (var i = 0; i < have.length; i++) {
            if (have[i] === "ping" || have[i] === "ip" || have[i] === "hwdata" || have[i] === "nc" || have[i] === "names" || have[i] === "mdns" || have[i] === "copy")
                parts.push(strings.t("tools." + have[i]))
        }
        return parts.join(". ")
    }

    Commons.Translations {
        id: strings
        directory: Qt.resolvedUrl("i18n")
    }

    component ActionRow: Rectangle {
        id: action
        property string label: ""
        property bool marked: false
        signal activated()
        width: parent ? parent.width : 0
        implicitHeight: Style.space(28)
        height: implicitHeight
        radius: Style.cornerRadius
        color: actionHit.containsMouse || marked ? Style.selectedFill : "transparent"

        Text {
            anchors.fill: parent
            anchors.leftMargin: Style.space(6)
            anchors.rightMargin: Style.space(6)
            textFormat: Text.PlainText
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
            color: action.marked ? Commons.Color.accent : Commons.Color.popups.text
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            text: action.label
        }

        MouseArea {
            id: actionHit
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: action.activated()
        }
    }

    component HostCells: Row {
        id: cells
        property var host: null
        property bool header: false
        property int indexHint: -1
        spacing: Style.space(8)

        Text {
            width: root.ipWidth
            height: cells.height
            textFormat: Text.PlainText
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
            color: cells.header ? Qt.darker(Commons.Color.popups.text, 1.3) : Commons.Color.popups.text
            font.family: Style.font.family
            font.pixelSize: cells.header ? Style.font.caption : Style.font.body
            text: cells.header ? strings.t("columns.ip") : ((cells.host && root.cursor === cells.indexHint ? "> " : "  ") + (cells.host ? Plain.plain(cells.host.ip, 15) : ""))
        }

        Repeater {
            model: root.shownColumns
            delegate: Text {
                required property var modelData
                width: modelData.width
                height: cells.height
                textFormat: Text.PlainText
                verticalAlignment: Text.AlignVCenter
                horizontalAlignment: modelData.id === "ms" ? Text.AlignRight : Text.AlignLeft
                elide: Text.ElideRight
                color: cells.header ? Qt.darker(Commons.Color.popups.text, 1.3) : Commons.Color.popups.text
                font.family: Style.font.family
                font.pixelSize: cells.header ? Style.font.caption : Style.font.body
                text: cells.header ? root.columnLabel(modelData.id) : root.cellText(cells.host, modelData.id)
            }
        }
    }

    PanelKeyCatcher {
        id: catcher
        anchors.fill: parent
        blocked: root.editing
        onMoveRequested: function(dx, dy) { if (dy !== 0) root.move(dy) }
        onActivateRequested: root.activate()
        onDeleteRequested: {
            // On the host list, x matches the dismiss button. On Options it
            // still lowers a column or removes a preset.
            if (root.page === "list" && root.hotkeyOfferVisible) {
                if (root.service)
                    root.service.dismissPanelHotkey()
                return
            }
            root.deletePreset()
        }
        onCloseRequested: {
            if (root.page !== "list")
                root.backToList()
            else
                root.closeRequested()
        }
        onTextKey: function(text) {
            var key = String(text || "")
            if (key === "s") {
                if (root.service && root.service.scanning)
                    root.service.stop()
                else if (root.service)
                    root.service.start()
            } else if (key === "r" && root.service) {
                root.service.redetect()
            } else if (key === "f") {
                root.openFilters()
            } else if (key === "o") {
                root.openOptions()
            } else if (key === "c" && root.service) {
                root.service.copyText(root.focusedText("ip"))
            } else if (key === "m" && root.service) {
                root.service.copyText(root.focusedText("mac"))
            } else if (key === "n" && root.service) {
                root.service.copyText(root.focusedText("hostname"))
            } else if (key === "e" && root.service) {
                root.service.exportHosts(root.rows)
            } else if (key === "w" && root.service) {
                var wakeHost = root.rememberedHost()
                if (wakeHost)
                    root.service.wake(wakeHost.mac)
            } else if (key === "v" && root.showWindowButton) {
                root.launchWindow()
            } else if ((key === "b" || key === "B") && root.service && (root.hotkeyOfferVisible || (root.page === "options" && root.optionsHotkeyVisible))) {
                root.service.setPanelHotkey()
            }
        }

        Column {
            id: column
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: root.showWindowButton ? undefined : parent.bottom
            spacing: Style.space(8)

            Item {
                id: hero
                width: parent.width
                implicitHeight: heroLabels.implicitHeight

                Column {
                    id: heroLabels
                    width: parent.width
                    spacing: Style.space(2)

                    Row {
                        id: titleRow
                        width: parent.width

                        Text {
                            id: titleText
                            textFormat: Text.PlainText
                            text: "Mellow IP Scan"
                            width: Math.min(implicitWidth, Math.max(0, titleRow.width - (openFull.visible ? openFull.implicitWidth + Style.space(8) : 0) - countPill.implicitWidth - Style.space(8)))
                            color: Commons.Color.popups.text
                            font.family: Style.font.family
                            font.pixelSize: Style.font.title
                            font.bold: true
                            elide: Text.ElideRight
                            anchors.verticalCenter: parent.verticalCenter
                        }

                        Item {
                            width: Math.max(0, titleRow.width - titleText.width - (openFull.visible ? openFull.implicitWidth + Style.space(8) : 0) - countPill.implicitWidth)
                            height: 1
                        }

                        Button {
                            id: openFull
                            visible: root.showWindowButton
                            anchors.verticalCenter: parent.verticalCenter
                            bordered: true
                            foreground: Commons.Color.popups.text
                            fontSize: Style.font.caption
                            horizontalPadding: Style.space(8)
                            verticalPadding: Style.space(2)
                            text: Plain.plain(strings.t("window.open"), 24)
                            onClicked: root.launchWindow()
                        }

                        Item {
                            width: openFull.visible ? Style.space(8) : 0
                            height: 1
                        }

                        BorderSurface {
                            id: countPill
                            implicitWidth: countText.implicitWidth + Style.space(10)
                            implicitHeight: countText.implicitHeight + Style.space(4)
                            anchors.verticalCenter: parent.verticalCenter
                            color: "transparent"
                            borderSpec: Border.controlSpec("normal", Commons.Color.popups.text, Commons.Color.accent)
                            radius: Style.cornerRadius

                            Text {
                                id: countText
                                textFormat: Text.PlainText
                                anchors.centerIn: parent
                                text: root.service ? Commons.I18n.formatNumber(root.service.aliveCount, 0) : "0"
                                color: Qt.darker(Commons.Color.popups.text, 1.4)
                                font.family: Style.font.family
                                font.pixelSize: Style.font.body
                                font.bold: true
                            }
                        }
                    }

                    Row {
                        id: hotkeyRow
                        visible: root.hotkeyOfferVisible
                        width: parent.width
                        height: visible ? implicitHeight : 0
                        spacing: Style.space(4)

                        Item {
                            width: Math.max(0, hotkeyRow.width - hotkeyOffer.implicitWidth - hotkeyDismiss.implicitWidth - hotkeyRow.spacing)
                            height: 1
                        }

                        Button {
                            id: hotkeyOffer
                            bordered: true
                            foreground: Commons.Color.popups.text
                            fontSize: Style.font.caption
                            horizontalPadding: Style.space(8)
                            verticalPadding: Style.space(4)
                            text: Plain.plain(strings.t("hotkey.offer"), 32)
                            onClicked: if (root.service) root.service.setPanelHotkey()
                        }

                        Button {
                            id: hotkeyDismiss
                            bordered: true
                            foreground: Commons.Color.popups.text
                            fontSize: Style.font.caption
                            horizontalPadding: Style.space(10)
                            verticalPadding: Style.space(4)
                            text: Plain.plain(strings.t("hotkey.dismiss"), 4)
                            tooltipText: Plain.plain(strings.t("hotkey.dismissTip"), 40)
                            onClicked: if (root.service) root.service.dismissPanelHotkey()
                        }
                    }

                    Text {
                        width: parent.width
                        textFormat: Text.PlainText
                        text: Plain.plain(root.progressLabel(), 80).toUpperCase()
                        visible: text !== ""
                        color: Qt.darker(Commons.Color.popups.text, 1.4)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        font.letterSpacing: 1.2
                        elide: Text.ElideRight
                    }
                }
            }

            Text {
                width: parent.width
                visible: root.showWindowButton && root.service && (root.service.hotkeyState === "ours" || root.service.hotkeyState === "taken" || root.service.hotkeyState === "broken")
                height: visible ? implicitHeight : 0
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
                color: root.service && root.service.hotkeyState === "ours" ? Qt.darker(Commons.Color.popups.text, 1.4) : Commons.Color.accent
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                text: {
                    if (!root.service)
                        return ""
                    if (root.service.hotkeyState === "ours")
                        return strings.t("hotkey.ours")
                    if (root.service.hotkeyState === "taken")
                        return strings.t("hotkey.taken")
                    if (root.service.hotkeyState === "broken")
                        return strings.t("hotkey.broken")
                    return ""
                }
            }

            Text {
                width: parent.width
                visible: root.statusLabel() !== ""
                textFormat: Text.PlainText
                color: Commons.Color.popups.text
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
                text: Plain.plain(root.statusLabel(), 160)
            }

            Column {
                id: listPage
                width: parent.width
                spacing: Style.space(4)
                visible: root.page === "list"
                height: visible ? implicitHeight : 0

                Text {
                    width: parent.width
                    textFormat: Text.PlainText
                    color: Qt.darker(Commons.Color.popups.text, 1.3)
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                    text: Plain.plain(root.service ? root.service.rangeText : "", 64)
                }

                Text {
                    width: parent.width
                    visible: root.toolWarning() !== ""
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                    color: Commons.Color.accent
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    text: root.toolWarning()
                }

                Item {
                    width: parent.width
                    height: root.rows.length > 0 ? Style.space(18) : 0
                    visible: root.rows.length > 0

                    HostCells {
                        x: Style.space(6)
                        width: parent.width - hostList.barGap - Style.space(12)
                        height: parent.height
                        header: true
                    }
                }

                Item {
                    id: listFrame
                    width: parent.width
                    // The dropdown stays a short sheet. The window uses whatever
                    // height is left under the title, so the cue means the view
                    // itself cannot show the rest.
                    height: {
                        var natural = Math.max(root.rows.length, 1) * root.rowHeight
                        if (root.showWindowButton)
                            return Math.min(natural, Style.space(280))
                        var detail = hostDetail.visible ? hostDetail.implicitHeight : 0
                        var tail = detail + hostActions.implicitHeight + keyHints.implicitHeight + listPage.spacing * (hostDetail.visible ? 3 : 2)
                        var room = column.height - listPage.y - y - tail
                        return Math.max(root.rowHeight, Math.min(natural, room))
                    }

                    readonly property color surface: Commons.Color.popups.background
                    readonly property color edge: Commons.Color.accent

                    Flickable {
                        id: hostList
                        anchors.fill: parent
                        contentHeight: hostColumn.implicitHeight
                        contentWidth: width
                        clip: true
                        interactive: contentHeight > height + 1
                        boundsBehavior: Flickable.StopAtBounds
                        flickableDirection: Flickable.VerticalFlick
                        readonly property bool overflow: contentHeight > height + 1
                        readonly property bool moreBelow: overflow && contentY + height < contentHeight - 1
                        readonly property bool moreAbove: contentY > 1
                        readonly property real barGap: overflow ? Style.space(10) : 0

                        ScrollBar.vertical: ScrollBar {
                            // The shell's scrollbar fades out until the list is
                            // touched, so keep a thin one on screen while rows
                            // are clipped.
                            policy: hostList.overflow ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                            contentItem: Rectangle {
                                implicitWidth: Style.space(4)
                                implicitHeight: Style.space(4)
                                radius: width / 2
                                color: Commons.Color.popups.text
                                opacity: 0.55
                            }
                        }

                        Column {
                            id: hostColumn
                            x: LayoutMirroring.enabled ? hostList.barGap : 0
                            width: hostList.width - hostList.barGap

                        Repeater {
                            model: root.rows.length
                            delegate: Rectangle {
                                id: hostRow
                                required property int index
                                readonly property var rowHost: root.rows[index]
                                width: hostColumn.width
                                height: root.rowHeight
                                radius: Style.cornerRadius
                                // Selection stays on the stronger fill. A row under the
                                // pointer uses the lighter hover fill, including while
                                // the list scrolls and the pointer rests on another host.
                                color: index === root.cursor ? Style.selectedFill : (hostHit.containsMouse ? Style.hoverFill : "transparent")

                                HostCells {
                                    anchors.fill: parent
                                    anchors.leftMargin: Style.space(6)
                                    anchors.rightMargin: Style.space(6)
                                    host: hostRow.rowHost
                                    indexHint: index
                                }

                                MouseArea {
                                    id: hostHit
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: root.selectHost(index)
                                    onDoubleClicked: {
                                        root.selectHost(index)
                                        if (root.service)
                                            root.service.copyText(root.focusedText("ip"))
                                    }
                                }
                            }
                        }

                            Text {
                                width: parent.width
                                visible: root.rows.length === 0
                                textFormat: Text.PlainText
                                color: Qt.darker(Commons.Color.popups.text, 1.3)
                                font.family: Style.font.family
                                font.pixelSize: Style.font.body
                                text: strings.t("row.empty")
                            }
                        }
                    }

                    // Same RGB as the popup. A transparent stop would fade through black.
                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: Style.space(28)
                        visible: hostList.moreBelow
                        enabled: false
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(listFrame.surface.r, listFrame.surface.g, listFrame.surface.b, 0) }
                            GradientStop { position: 1.0; color: Qt.rgba(listFrame.surface.r, listFrame.surface.g, listFrame.surface.b, listFrame.surface.a * 0.55) }
                        }
                    }
                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: Style.space(16)
                        visible: hostList.moreBelow
                        enabled: false
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(listFrame.edge.r, listFrame.edge.g, listFrame.edge.b, 0) }
                            GradientStop { position: 1.0; color: Qt.rgba(listFrame.edge.r, listFrame.edge.g, listFrame.edge.b, 0.22) }
                        }
                    }
                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        height: Style.space(16)
                        visible: hostList.moreAbove
                        enabled: false
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: listFrame.surface }
                            GradientStop { position: 1.0; color: Qt.rgba(listFrame.surface.r, listFrame.surface.g, listFrame.surface.b, 0) }
                        }
                    }
                }

                Text {
                    id: hostDetail
                    width: parent.width
                    visible: text !== ""
                    height: visible ? implicitHeight : 0
                    textFormat: Text.PlainText
                    elide: Text.ElideRight
                    color: Commons.Color.popups.text
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    text: {
                        if (!root.focused || root.rows.length === 0)
                            return ""
                        var parts = []
                        if (!root.columnShown("mac"))
                            parts.push(root.focused.mac ? Plain.plain(root.focused.mac, 17) : strings.t("row.unresolved"))
                        if (!root.columnShown("vendor"))
                            parts.push(root.focused.vendor ? Plain.plain(root.focused.vendor, 64) : strings.t("row.unresolved"))
                        if (!root.columnShown("ports")) {
                            var ports = root.focused.ports || []
                            var portText = ""
                            for (var i = 0; i < ports.length; i++)
                                portText += (portText ? " " : "") + ports[i]
                            parts.push(portText ? Plain.plain(portText, 64) : strings.t("row.unresolved"))
                        }
                        if (!root.columnShown("source") && root.focused.hostnameSource)
                            parts.push(root.cellText(root.focused, "source"))
                        return parts.join("  ")
                    }
                }

                Row {
                    id: hostActions
                    width: parent.width
                    spacing: root.actionGap

                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(root.service && root.service.scanning ? strings.t("mouse.stop") : strings.t("mouse.scan"), 16)
                        onClicked: {
                            if (!root.service)
                                return
                            if (root.service.scanning)
                                root.service.stop()
                            else
                                root.service.start()
                        }
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.filters"), 16)
                        onClicked: root.openFilters()
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.options"), 16)
                        onClicked: root.openOptions()
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.copyIp"), 16)
                        onClicked: if (root.service) root.service.copyText(root.focusedText("ip"))
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.copyMac"), 16)
                        onClicked: if (root.service) root.service.copyText(root.focusedText("mac"))
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.copyName"), 16)
                        onClicked: if (root.service) root.service.copyText(root.focusedText("hostname"))
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.export"), 16)
                        onClicked: if (root.service) root.service.exportHosts(root.rows)
                    }
                    Button {
                        bordered: true
                        foreground: Commons.Color.popups.text
                        fontSize: Style.font.caption
                        horizontalPadding: root.actionPad
                        verticalPadding: Style.space(4)
                        text: Plain.plain(strings.t("mouse.wake"), 16)
                        onClicked: {
                            var wakeHost = root.rememberedHost()
                            if (root.service && wakeHost)
                                root.service.wake(wakeHost.mac)
                        }
                    }
                }

                Text {
                    id: keyHints
                    width: parent.width
                    textFormat: Text.PlainText
                    wrapMode: Text.NoWrap
                    elide: Text.ElideRight
                    color: Qt.darker(Commons.Color.popups.text, 1.35)
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    text: root.showWindowButton ? strings.t("keys.panel") : strings.t("keys.list")
                }
            }

            Column {
                width: parent.width
                spacing: Style.space(6)
                visible: root.page === "filters"
                height: visible ? implicitHeight : 0

                PanelSectionHeader {
                    text: strings.t("filter.title")
                    foreground: Commons.Color.popups.text
                }
                Toggle {
                    width: parent.width
                    label: strings.t("filter.hideDead")
                    checked: root.service ? root.service.hideDead : true
                    hasCursor: root.cursor === 0
                    foreground: Commons.Color.popups.text
                    onClicked: if (root.service) root.service.saveSettings({ hideDead: !root.service.hideDead })
                }
                Toggle {
                    width: parent.width
                    label: strings.t("filter.openPorts")
                    checked: root.service ? root.service.openPortsOnly : false
                    hasCursor: root.cursor === 1
                    foreground: Commons.Color.popups.text
                    onClicked: if (root.service) root.service.saveSettings({ openPortsOnly: !root.service.openPortsOnly })
                }
                Column {
                    width: parent.width
                    spacing: Style.space(2)

                    Text {
                        width: parent.width
                        textFormat: Text.PlainText
                        color: Qt.darker(Commons.Color.popups.text, 1.35)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        text: strings.t("filter.query")
                    }
                    PlainLine {
                        id: queryLine
                        width: parent.width
                        maximumLength: 64
                        placeholder: strings.t("filter.queryExample")
                        selected: root.page === "filters" && root.cursor === 2
                        text: root.query
                        onStarted: root.quietOthers(queryLine)
                        onAccepted: function(value) {
                            root.query = value
                            root.focusKeys()
                        }
                        onDismissed: root.focusKeys()
                    }
                }
                Column {
                    width: parent.width
                    spacing: Style.space(2)

                    Text {
                        width: parent.width
                        textFormat: Text.PlainText
                        color: Qt.darker(Commons.Color.popups.text, 1.35)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        text: strings.t("filter.latency")
                    }
                    PlainLine {
                        id: latencyLine
                        width: parent.width
                        maximumLength: 6
                        placeholder: strings.t("filter.latencyExample")
                        selected: root.page === "filters" && root.cursor === 3
                        text: root.service && root.service.maxLatencyMs > 0 ? String(root.service.maxLatencyMs) : ""
                        onStarted: root.quietOthers(latencyLine)
                        onAccepted: function(value) {
                            var number = parseInt(value, 10)
                            if (root.service)
                                root.service.saveSettings({ maxLatencyMs: isFinite(number) ? number : 0 })
                            root.focusKeys()
                        }
                        onDismissed: root.focusKeys()
                    }
                }
                ActionRow {
                    label: strings.t("mouse.back")
                    onActivated: root.backToList()
                }
                Text {
                    textFormat: Text.PlainText
                    color: Qt.darker(Commons.Color.popups.text, 1.35)
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    text: strings.t("keys.back")
                }
            }

            Column {
                width: parent.width
                spacing: Style.space(6)
                visible: root.page === "options"
                height: visible ? implicitHeight : 0

                Button {
                    visible: root.optionsHotkeyVisible
                    height: visible ? implicitHeight : 0
                    bordered: true
                    foreground: Commons.Color.popups.text
                    fontSize: Style.font.caption
                    horizontalPadding: Style.space(8)
                    verticalPadding: Style.space(4)
                    text: Plain.plain(strings.t("hotkey.offer"), 32)
                    onClicked: if (root.service) root.service.setPanelHotkey()
                }
                PanelSectionHeader {
                    text: strings.t("options.title")
                    foreground: Commons.Color.popups.text
                }
                PlainLine {
                    id: rangeLine
                    width: parent.width
                    maximumLength: 64
                    placeholder: strings.t("options.range")
                    selected: root.optionCursorUsed && root.page === "options" && root.cursor === 0
                    text: root.service ? root.service.rangeText : ""
                    onStarted: root.quietOthers(rangeLine)
                    onAccepted: function(value) {
                        if (root.service)
                            root.service.saveSettings({ range: value })
                        root.focusKeys()
                    }
                    onDismissed: root.focusKeys()
                }
                ActionRow {
                    label: strings.t("options.detect")
                    marked: root.cursor === 1
                    onActivated: {
                        root.cursor = 1
                        if (root.service)
                            root.service.redetect()
                    }
                }
                Toggle {
                    width: parent.width
                    label: strings.t("options.portsToggle")
                    checked: root.service ? root.service.portChecks : false
                    hasCursor: root.cursor === 2
                    foreground: Commons.Color.popups.text
                    onClicked: if (root.service) root.service.saveSettings({ portChecks: !root.service.portChecks })
                }
                PlainLine {
                    id: portsLine
                    width: parent.width
                    maximumLength: 64
                    placeholder: strings.t("options.ports")
                    selected: root.optionCursorUsed && root.page === "options" && root.cursor === 3
                    text: root.service ? root.service.portsText : ""
                    onStarted: root.quietOthers(portsLine)
                    onAccepted: function(value) {
                        if (root.service)
                            root.service.saveSettings({ ports: value })
                        root.focusKeys()
                    }
                    onDismissed: root.focusKeys()
                }
                PanelSectionHeader {
                    text: strings.t("columns.title")
                    foreground: Commons.Color.popups.text
                }
                Repeater {
                    model: root.columnSlots
                    delegate: Rectangle {
                        required property int index
                        readonly property string columnId: root.columnIds[index] || ""
                        width: parent.width
                        height: root.rowHeight
                        radius: Style.cornerRadius
                        color: root.cursor === root.columnBase + index || columnHit.containsMouse ? Style.selectedFill : "transparent"

                        Text {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(6)
                            anchors.rightMargin: lowerLabel.width + Style.space(12)
                            textFormat: Text.PlainText
                            verticalAlignment: Text.AlignVCenter
                            elide: Text.ElideRight
                            color: root.cursor === root.columnBase + index ? Commons.Color.accent : Commons.Color.popups.text
                            font.family: Style.font.family
                            font.pixelSize: Style.font.body
                            text: (index + 1) + "  " + root.columnLabel(columnId)
                        }
                        Text {
                            id: lowerLabel
                            anchors.right: parent.right
                            anchors.rightMargin: Style.space(6)
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            color: lowerHit.containsMouse ? Commons.Color.accent : Qt.darker(Commons.Color.popups.text, 1.2)
                            font.family: Style.font.family
                            font.pixelSize: Style.font.caption
                            text: strings.t("columns.lower")
                        }
                        MouseArea {
                            id: columnHit
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            anchors.right: lowerHit.left
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                root.cursor = root.columnBase + index
                                root.moveColumn(index, -1)
                            }
                        }
                        MouseArea {
                            id: lowerHit
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: lowerLabel.implicitWidth + Style.space(12)
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                root.cursor = root.columnBase + index
                                root.moveColumn(index, 1)
                            }
                        }
                    }
                }
                Text {
                    width: parent.width
                    visible: root.toolWarning() !== ""
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                    color: Commons.Color.accent
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    text: root.toolWarning()
                }
                PlainLine {
                    id: presetLine
                    width: parent.width
                    maximumLength: 32
                    placeholder: strings.t("options.preset")
                    selected: root.optionCursorUsed && root.page === "options" && root.cursor === root.presetField
                    onStarted: root.quietOthers(presetLine)
                    onAccepted: function(value) {
                        presetLine.text = value
                        root.focusKeys()
                    }
                    onDismissed: root.focusKeys()
                }
                ActionRow {
                    label: strings.t("options.save")
                    marked: root.cursor === root.saveSlot
                    onActivated: {
                        root.cursor = root.saveSlot
                        root.savePreset()
                    }
                }
                Repeater {
                    model: root.presets.length
                    delegate: Rectangle {
                        required property int index
                        readonly property var preset: root.presets[index]
                        width: parent.width
                        height: root.rowHeight
                        radius: Style.cornerRadius
                        color: root.cursor === root.presetBase + index || presetHit.containsMouse ? Style.selectedFill : "transparent"

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(6)
                            anchors.rightMargin: Style.space(6)
                            spacing: Style.space(8)

                            Text {
                                width: parent.width - removeLabel.width - parent.spacing
                                height: parent.height
                                textFormat: Text.PlainText
                                verticalAlignment: Text.AlignVCenter
                                elide: Text.ElideRight
                                color: root.cursor === root.presetBase + index ? Commons.Color.accent : Commons.Color.popups.text
                                font.family: Style.font.family
                                font.pixelSize: Style.font.body
                                text: Plain.plain(preset.name, 32) + "  " + Plain.plain(preset.range, 64)
                            }
                            Text {
                                id: removeLabel
                                height: parent.height
                                textFormat: Text.PlainText
                                verticalAlignment: Text.AlignVCenter
                                color: removeHit.containsMouse ? Commons.Color.accent : Qt.darker(Commons.Color.popups.text, 1.2)
                                font.family: Style.font.family
                                font.pixelSize: Style.font.caption
                                text: strings.t("mouse.remove")
                            }
                        }

                        MouseArea {
                            id: presetHit
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            anchors.right: removeHit.left
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                root.cursor = root.presetBase + index
                                if (root.service && preset)
                                    root.service.saveSettings({ range: preset.range })
                            }
                        }
                        MouseArea {
                            id: removeHit
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: removeLabel.implicitWidth + Style.space(12)
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                root.cursor = root.presetBase + index
                                root.deletePreset()
                            }
                        }
                    }
                }
                ActionRow {
                    label: strings.t("mouse.back")
                    onActivated: root.backToList()
                }
                Text {
                    width: parent.width
                    wrapMode: Text.NoWrap
                    elide: Text.ElideRight
                    textFormat: Text.PlainText
                    color: Qt.darker(Commons.Color.popups.text, 1.35)
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    text: strings.t("keys.options")
                }
            }
        }
    }

    function activate() {
        if (!service)
            return
        if (page === "list") {
            service.copyText(focusedText("ip"))
            return
        }
        if (page === "filters") {
            if (cursor === 0)
                service.saveSettings({ hideDead: !service.hideDead })
            else if (cursor === 1)
                service.saveSettings({ openPortsOnly: !service.openPortsOnly })
            else if (cursor === 2)
                queryLine.begin()
            else if (cursor === 3)
                latencyLine.begin()
            return
        }
        if (cursor === 0)
            rangeLine.begin()
        else if (cursor === 1)
            service.redetect()
        else if (cursor === 2)
            service.saveSettings({ portChecks: !service.portChecks })
        else if (cursor === 3)
            portsLine.begin()
        else if (cursor >= columnBase && cursor < columnBase + columnSlots)
            moveColumn(cursor - columnBase, -1)
        else if (cursor === presetField)
            presetLine.begin()
        else if (cursor === saveSlot)
            savePreset()
        else if (cursor >= presetBase && presets[cursor - presetBase])
            service.saveSettings({ range: presets[cursor - presetBase].range })
    }
}
