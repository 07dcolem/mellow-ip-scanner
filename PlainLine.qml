import QtQuick
import qs.Commons
import qs.Commons as Commons

// One plain line. No clipboard, and no Qt text control. A click starts
// editing and places the caret. Keys exist only while editing is true.
Item {
    id: root

    property string text: ""
    property string placeholder: ""
    property bool selected: false
    property int maximumLength: 64
    property bool editing: false
    property int cursor: 0
    property string draft: ""

    signal accepted(string value)
    signal dismissed()
    signal started()

    implicitWidth: parent ? parent.width : Style.space(200)
    implicitHeight: Math.max(label.implicitHeight + Style.space(8), Style.space(28))
    focus: editing

    function begin() {
        draft = text
        cursor = draft.length
        editing = true
        forceActiveFocus()
        started()
    }

    function abandon() {
        editing = false
        draft = text
    }

    function indexAt(x) {
        var source = draft
        var local = x - Style.space(4)
        if (local <= 0 || source.length === 0)
            return 0
        var width = 0
        for (var i = 0; i < source.length; i++) {
            var advance = metrics.advanceWidth(source.charAt(i))
            if (width + advance * 0.5 >= local)
                return i
            width += advance
        }
        return source.length
    }

    function commit() {
        editing = false
        accepted(draft.slice(0, maximumLength))
    }

    function cancelEdit() {
        editing = false
        draft = text
        dismissed()
    }

    FontMetrics {
        id: metrics
        font.family: label.font.family
        font.pixelSize: label.font.pixelSize
    }

    // The example stays faded in the field until there is text, including
    // while the row is highlighted and while the caret is in an empty draft.
    readonly property bool showPlaceholder: placeholder !== "" && (editing ? draft : text) === ""

    Rectangle {
        anchors.fill: parent
        radius: Style.cornerRadius
        color: root.editing || root.selected || fieldMouse.containsMouse ? Style.selectedFill : "transparent"
        border.color: root.editing || root.selected ? Style.selectedBorderColor : Style.normalBorderColor
        border.width: 1
    }

    Text {
        id: label
        anchors.fill: parent
        anchors.margins: Style.space(4)
        textFormat: Text.PlainText
        verticalAlignment: Text.AlignVCenter
        elide: root.editing ? Text.ElideNone : Text.ElideRight
        color: root.showPlaceholder ? Qt.rgba(Commons.Color.popups.text.r, Commons.Color.popups.text.g, Commons.Color.popups.text.b, 0.45) : Commons.Color.popups.text
        font.family: Style.font.family
        font.italic: root.showPlaceholder
        font.pixelSize: Style.font.body
        text: {
            if (root.showPlaceholder)
                return root.placeholder
            if (!root.editing)
                return root.text
            return root.draft
        }
    }

    Rectangle {
        visible: root.editing
        width: 1
        height: label.font.pixelSize
        x: label.x + metrics.advanceWidth(root.draft.slice(0, root.cursor))
        anchors.verticalCenter: parent.verticalCenter
        color: Commons.Color.popups.text
    }

    MouseArea {
        id: fieldMouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.IBeamCursor
        acceptedButtons: Qt.LeftButton
        onPressed: function(mouse) {
            if (!root.editing)
                root.begin()
            root.cursor = root.indexAt(mouse.x)
        }
    }

    Keys.onPressed: function(event) {
        if (!root.editing)
            return
        if (event.key === Qt.Key_Escape) {
            root.cancelEdit()
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            root.commit()
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_Backspace) {
            if (root.cursor > 0) {
                root.draft = root.draft.slice(0, root.cursor - 1) + root.draft.slice(root.cursor)
                root.cursor--
            }
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_Delete) {
            root.draft = root.draft.slice(0, root.cursor) + root.draft.slice(root.cursor + 1)
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_Left) {
            root.cursor = Math.max(0, root.cursor - 1)
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_Right) {
            root.cursor = Math.min(root.draft.length, root.cursor + 1)
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_Home) {
            root.cursor = 0
            event.accepted = true
            return
        }
        if (event.key === Qt.Key_End) {
            root.cursor = root.draft.length
            event.accepted = true
            return
        }
        if (event.text && event.text.length === 1 && (event.modifiers & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)) === 0) {
            var code = event.text.charCodeAt(0)
            if (code >= 32 && code < 127 && root.draft.length < root.maximumLength) {
                root.draft = root.draft.slice(0, root.cursor) + event.text + root.draft.slice(root.cursor)
                root.cursor++
            }
            event.accepted = true
        }
    }
}
