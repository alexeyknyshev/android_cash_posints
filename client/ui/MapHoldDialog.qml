import QtQuick 2.0
import QtQuick.Controls 1.3

Item {
    id: dialog
    anchors.centerIn: parent
    width: parent.width * 0.9
    height: parent.height * 0.9

    function show() {
        opacityShow.running = true
    }

    function hide() {
        opacityHide.running = true
    }

    Rectangle {
        id: rect
        anchors.fill: parent

        PropertyAnimation {
            id: opacityShow
            target: rect
            property: "opacity"
            from: 0
            to: 0.9
            duration: 400
            onStarted: dialog.visible = true
        }

        PropertyAnimation {
            id: opacityHide
            target: rect
            property: "opacity"
            from: 0.9
            to: 0
            duration: 400
            onStopped: dialog.visible = false
        }

        color: "white"
        opacity: 0.9
        radius: dialog.width / 32

//        Menu {
//            id: test

//            MenuItem {
//                text: "MenuItem_1"
//            }
//            MenuItem {
//                text: "MenuItem_2"
//            }
//        }

        Column {
            z: parent.z + 1
            anchors.centerIn: parent
            width: parent.width * 0.9
            height: parent.height * 0.9
            spacing: 5

            Button {
                anchors.left: parent.left
                anchors.right: parent.right
                height: dialog.height / 8
                id: addCashPointButton
                text: qsTr("Добавить банкомат")
            }
            Button {
                anchors.left: parent.left
                anchors.right: parent.right
                height: dialog.height / 8
                id: findCashPointNearbyButton
                text: qsTr("Найти ближайший банкомат")
            }
            Button {
                anchors.left: parent.left
                anchors.right: parent.right
                height: dialog.height / 8
                id: name3
                text: qsTr("text3")
            }

        }

        MouseArea {
            anchors.fill: parent
        }
    }
}

