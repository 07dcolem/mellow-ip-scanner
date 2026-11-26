import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Plain.js" as Plain

BarWidget {
    id: root

    moduleName: "io.github.07dcolem.mellow-ip-scan"

    property bool opened: false
    property var scanner: null
    property int lookupTicks: 0

    readonly property int alive: scanner ? scanner.aliveCount : 0
    readonly property bool scanning: scanner ? scanner.scanning : false

    function open() { opened = true }
    function close() { opened = false }

    function refreshScanner() {
        var facade = bar && bar.shell
        scanner = facade && facade.serviceFor ? facade.serviceFor(moduleName) : null
        if (scanner)
            scanner.noteSettings(settings)
    }

    onBarChanged: refreshScanner()
    onSettingsChanged: if (scanner) scanner.noteSettings(settings)
    Component.onCompleted: refreshScanner()

    Timer {
        interval: 400
        repeat: root.scanner === null && root.lookupTicks < 20
        running: root.scanner === null && root.lookupTicks < 20
        onTriggered: {
            root.lookupTicks++
            root.refreshScanner()
        }
    }

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight

    Commons.Translations {
        id: strings
        directory: Qt.resolvedUrl("i18n")
    }

    WidgetButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        active: root.scanning
        text: root.vertical
            ? String(root.alive)
            : ((root.scanning ? "\u2026 " : "IP ") + root.alive)
        tooltipText: Plain.plain(strings.t("bar.tooltip").arg(root.alive), 160)
        onPressed: function(mouseButton) {
            root.refreshScanner()
            if (mouseButton === Qt.MiddleButton) {
                if (!root.scanner)
                    return
                if (root.scanner.scanning)
                    root.scanner.stop()
                else
                    root.scanner.start()
            } else if (mouseButton === Qt.RightButton) {
                if (root.scanner)
                    root.scanner.redetect()
            } else {
                root.opened = !root.opened
            }
        }
    }

    KeyboardPanel {
        id: panel
        anchorItem: button
        owner: root
        bar: root.bar
        open: root.opened
        focusTarget: panel.loadedContent
        // 420px of card is 388px of text after popup padding and the border.
        // The caption key line is 390px in the 10px monospace face, so "w wake" was cut to "w wa…".
        contentWidth: panel.fittedContentWidth(Style.space(460))
        contentHeight: panel.fittedContentHeight(panel.loadedContentHeight)

        content: ScanView {
            service: root.scanner
            onCloseRequested: root.close()
        }
    }
}
