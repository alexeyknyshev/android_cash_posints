import QtQuick 2.0

Text {
    anchors.left: parent.left
    anchors.right: parent.right
    wrapMode: Text.WordWrap
    font.pixelSize: 36
    MouseArea {
        anchors.fill: parent
        onEntered: parent.color = "blue"
        onExited: parent.color = ""
        onClicked: console.log("MHDItem (" + parent.text + ") clicked!")
    }
}
