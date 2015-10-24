import QtQuick 2.0
//import QtQuick.Controls 1.2

//ApplicationWindow {
//    visible: true
//    height: 800
//    width: 600

Rectangle {
    id: upperButton
    //color: "blue"
//    anchors.fill: parent

    signal enabledChanged(bool isEnabled)

    Rectangle {
        id: _upperButtonFirst
        anchors.left: parent.left
        anchors.leftMargin: parent.width * 0.04
        anchors.bottom: parent.bottom
        anchors.bottomMargin: anchors.leftMargin
        color: parent.state == "enabled" ? "pink": "lightblue"
        height: parent.state == "enabled" ? parent.height : parent.height * 0.5
        width: parent.width * 0.16

        Behavior on height {
            PropertyAnimation {
                duration: 200
//                easing.type: Easing.InOutCubic
            }
        }

        Behavior on color {
            ColorAnimation {
                duration: 200
            }
        }
    }

    Rectangle {
        id: _upperButtonSecond
        anchors.bottom: parent.bottom
        anchors.bottomMargin: parent.width * 0.04
        anchors.horizontalCenter: parent.horizontalCenter
        color: "lightblue"
        width: parent.width * 0.16
        height: parent.height * 0.5
    }

    Rectangle {
        id: _upperButtonThird
        anchors.bottom: parent.bottom
        anchors.bottomMargin: parent.width * 0.04
        anchors.right: parent.right
        anchors.rightMargin: anchors.bottomMargin
        color: "lightblue"
        width: parent.width * 0.16
        height: parent.height * 0.5
    }

    states: [
        State {
            name: "enabled"
        }
    ]

    onStateChanged: {
        enabledChanged(state == "enabled")
    }

//    onEnabledChanged: {
//        console.log(isEnabled)
//    }

    MouseArea {
        anchors.fill: parent
        onClicked: parent.state == "" ? parent.state = "enabled" : parent.state = ""
    }
}

//}

