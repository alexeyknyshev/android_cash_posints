import QtQuick 2.4
import QtQuick.Controls 1.3
import QtQuick.Window 2.2
import QtQuick.Dialogs 1.2
import QtGraphicalEffects 1.0
import QtQml 2.2

import "viewloadercreator.js" as ViewLoaderCreator

ApplicationWindow {
    title: qsTr("Cash Points")
    width: 640
    height: 480
    visible: true

    objectName: "appWindow"
    signal pong(bool ok)
    onPong: {
        if (ok) {
            console.log("pong :)")
        } else {
            console.warn("pong :(")
        }
    }

    property date lastExitAttempt: new Date()
    property int backExitThreathold: 500

    onClosing: {
        if (Qt.platform.os == "android") {
            if (!flipable.flipped) {
                flipable.flipped = true
            } else {
                console.log("exit")
                var currentTime = new Date()
                if (currentTime.valueOf() - lastExitAttempt.valueOf() < backExitThreathold) {
                    close.accepted = true
                    return
                }
                lastExitAttempt = currentTime
            }
            close.accepted = false
        } else {
            close.accepted = mapView.aboutToClose()
        }
    }
    Keys.onReleased: {
        if (event.key == Qt.Key_Back) {
            console.log("Back button captured - wunderbar !")
            event.accepted = true
        }
    }

    Flipable {
        id: flipable
        anchors.fill: parent
        //focus: true

        function onBankListCreated() {

        }

        Keys.onEscapePressed: {
            if (flipped) {
                flipped = !flipped
            }
        }

        Keys.onPressed: {
            console.log("here")
            if (event.key === Qt.Key_Tab) {
                if (!flipped) {
                    flipped = !flipped
                }
            }
        }

        property bool flipped: false
        states: State
                {
                    name: "back"
                    PropertyChanges {
                        target: rotation
                        angle: 180
                    }

                    when: flipable.flipped
                }
        transitions: Transition
                     {
                        NumberAnimation {
                            target: rotation
                            properties: "angle"
                            duration: 1500
                            easing.type: Easing.InOutQuad
                        }
                     }

        transform: [ Rotation
                     {
                        id: rotation
                        origin.x: flipable.width / 2
                        origin.y: flipable.height / 2
                        axis.x: 0; axis.y: 1; axis.z: 0     // set axis.y to 1 to rotate around y-axis
                        angle: 0    // the default angle
                     }
                   ]


        front:
        Item {
            enabled: !parent.flipped
            anchors.fill: parent

            Label {
                id: logo
                anchors.centerIn: parent
                text: "Cash Points"
                font.pixelSize: 96
                color: "blue"
                fontSizeMode: Text.HorizontalFit
                property bool initialized: false

                MouseArea {
                    anchors.fill: parent
                    onClicked:
                        if (logo.state == "")
                        {
                            logo.state = "animationStart"
                            flipable.flipped = !flipable.flipped
                        } else {
                            console.warn("test")
                        }
                }

                states: [
                    State {
                        name: "animationStart"
                        PropertyChanges {
                            target: logo
                            color: "lightgray"
                        }
                        onCompleted: logo.state = "animationEnd"
                    },
                    State {
                        name: "animationEnd"
                        PropertyChanges {
                            target: logo
                            color: "black"
                        }
                        onCompleted: logo.state = "animationStart"
                    } ]

                transitions: [
                    Transition {
                        from: ""
                        to: "animationStart"

                        ColorAnimation {
                            target: logo
                            duration: 2000
                        }
                    },
                    Transition {
                        from: "animationStart"
                        to: "animationEnd"

                        ColorAnimation {
                            target: logo
                            duration: 2000
                        }
                    },
                    Transition {
                        from: "animationEnd"
                        to: "animationStart"

                        ColorAnimation {
                            target: logo
                            duration: 2000
                        }
                    },
                    Transition {
                        from: "*"
                        to: ""

                        ColorAnimation {
                            target: logo
                            duration: 2000
                        }
                    }
                ]
            }

            BusyIndicator {
                id: progress
                //anchors.centerIn: parent
                anchors.top: logo.bottom
                anchors.horizontalCenter: logo.horizontalCenter
//                value: 0.8
            }

//            ProgressBar
//            {
//                id: progress
//                //anchors.centerIn: parent
//                anchors.top: logo.bottom
//                anchors.horizontalCenter: logo.horizontalCenter
//                value: 0.8
//            }
        }
        back:
        MapView {
            id: mapView
            enabled: parent.flipped
            anchors.fill: parent

            active: !leftMenu.visible

            LeftMenu {
                id: leftMenu
                x: 0
                z: mapView.z + 10
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: parent.width * 0.6

                onItemClicked: {
                    if (itemName && itemName.length > 0) {
                        ViewLoaderCreator.createViewLoader(function(loader) {
                            loader.setView(itemName)
                        })
                        flipable.flipped = !flipable.flipped
                    }
                }
            }

            RectangularGlow {
                visible: leftMenu.visible
                anchors.fill: leftMenu
                z: leftMenu.z - 1
                glowRadius: leftMenu.height / 10
                spread: 0.1
                color: "#0000000FF"
                cornerRadius: glowRadius
                opacity: (leftMenu.x + leftMenu.width) / (mapView.width * 0.6)
            }

            onClicked: {
                leftMenu.state = "hidden"
            }

            onMenuClicked: {
                leftMenu.state = ""
            }
        }


//        Desaturate {
//            anchors.top: mapView.top
//            anchors.left: leftMenu.right
//            anchors.right: mapView.right
//            anchors.bottom: mapView.bottom
//            source: mapView
//            desaturation: 0.8
////            z: leftMenu.z - 1
//        }
    }
}
