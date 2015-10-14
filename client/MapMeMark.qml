import QtQuick 2.4
import QtLocation 5.3

MapQuickItem {
    anchorPoint.x: image.width / 2
    anchorPoint.y: image.height
    sourceItem: Image {
        id: image
        source: "ico/marker.png"

        Text {
            text: qsTr("Я")
            fontSizeMode: Text.Fit
            verticalAlignment: Text.AlignVCenter

            anchors.verticalCenter: parent.verticalCenter
            anchors.verticalCenterOffset: -(parent.height / 8)
            anchors.horizontalCenterOffset: -1
            anchors.horizontalCenter: parent.horizontalCenter
        }
   }
}
