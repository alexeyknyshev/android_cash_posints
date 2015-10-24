import QtQuick 2.3
import QtQuick.Controls 1.2

//ApplicationWindow {
//    visible: true
//    height: 800
//    width: 600

Rectangle {
    SystemPalette {
        id: sysPalette
        colorGroup: SystemPalette.Active
    }

    property bool hidden: false

    states: State {
        name: "hidden"
        when: hidden
        PropertyChanges {
            target: topItem
            x: -width
        }
    }
    transitions: [
        Transition {
            from: ""
            to: "hidden"
            PropertyAnimation {
                duration: 500
                easing.type: Easing.InQuad
                properties: "x"
            }
            onRunningChanged: {
                if (!running) {
                    visible = false
                }
            }
        },
        Transition {
            from: "hidden"
            to: ""
            PropertyAnimation {
                duration: 500
                easing.type: Easing.OutQuad
                properties: "x"
            }
            onRunningChanged: {
                if (running) {
                    console.log("I'm here")
                    visible = true
                }
            }
        }
    ]

    id: topItem

    color: sysPalette.window

    property bool isAboutToHide: false

    signal itemClicked(string itemName)

    MultiPointTouchArea {
        anchors.fill: parent

//        onPositionChanged: {
//            console.log("moved 1")
//        }

        onGestureStarted: {
            console.log("gesture started")
            console.log(gesture.toString())
        }

        onTouchUpdated: {
            if (touchPoints.length === 0)
                return

            console.log("touch upd")

            console.log(touchPoints[0].velocity)
            if (touchPoints[0].velocity.length() > parent.width * 0.3) {
                console.log("hide!")
            }

            for (var i = 0; i < touchPoints.length; i++) {
//                console.log("point " + i + ": " + touchPoints[i].x + " " + touchPoints[i].y)
            }
        }

        Rectangle {
            id: userAccountView
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: parent.height * 0.3

            Label {
                id: registerInfo
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: 20

                wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                text: qsTr("<b>Зарегистрируйтесь!</b>\nРегистрация вам позволит...!")
            }

            Rectangle {
                id: registerButton
                anchors.top: registerInfo.bottom
                anchors.left: parent.left
                anchors.right: parent.right
    //            anchors.bottom: parent.bottom
                anchors.margins: 20
                visible: topItem.visible

                height: buttonText.contentHeight * 5

                color: "#3295BA"

                Text {
                    id: buttonText
                    anchors.fill: parent
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    text: qsTr("Зарегистрироваться")
                    color: "white"
                    fontSizeMode: Text.VerticalFit
                    renderType: Text.NativeRendering
                    visible: topItem.visible
                }

                states: State {
                    name: "clicked"
                    PropertyChanges {
                        target: registerButton
                        color: "#29BCF2"
                    }
                }

                transitions: Transition {
                    ColorAnimation {
                        duration: 100
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    onPressed: {
                        registerButton.state = "clicked"
                        console.log("pressed")
                    }
                    onReleased: {
                        registerButton.state = ""
                    }
                }
            }
        }

        ListModel {
            id: menuModel

            ListElement {
                name: "bankSelectionItem"
                text: qsTr("Мои банки")
                ico: "../icon/bank.svg"
                property string qmlfile: "BanksList.qml"
            }
            ListElement {
                name: "townSelectionItem"
                text: qsTr("Мои города")
                ico: "../icon/town.svg"
                property string qmlfile: "TownList.qml"
            }
            ListElement {
                name: "settingsSelectionItem"
                text: qsTr("Настройки")
                ico: "../icon/settings.svg"
                property string qmlfile: ""
            }
            ListElement {
                name: "helpSelectonItem"
                text: qsTr("Помощь")
                ico: "../icon/info.svg"
                property string qmlfile: ""
            }
            ListElement {
                name: "feedbackSelectionItem"
                text: qsTr("Оставить отзыв")
                ico: "../icon/like.svg"
                property string qmlfile: ""
            }
            ListElement {
                name: "bugreportSelectionItem"
                text: qsTr("Сообщить об ошибке")
                ico: "../icon/bug.svg"
            }
        }

        ScrollView {
            anchors.top: userAccountView.bottom
            anchors.left:parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            verticalScrollBarPolicy: Qt.ScrollBarAlwaysOff

            ListView {
                id: menu
                model: menuModel
                delegate: Rectangle {
                    z: parent.z + 1
                    id: itemContatiner
                    height: menu.height * 0.2
                    width: parent.width

                    color: "white"

                    Image {
                        id: itemImageView
                        anchors.top: parent.top
                        anchors.topMargin: itemContatiner.height * 0.25
                        anchors.left: parent.left
                        anchors.rightMargin: anchors.topMargin
    //                    anchors.left: parent.left
                        anchors.leftMargin: anchors.topMargin
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: anchors.topMargin
                        fillMode: Image.PreserveAspectFit
                        mipmap: true

    //                    height: itemTextView.contentHeight


                        source: model.ico
                        width: height
                    }

                    Label {
                        id: itemTextView
                        anchors.top: parent.top
                        anchors.right: parent.right
                        anchors.rightMargin: height * 0.25
                        anchors.left: itemImageView.right
                        anchors.leftMargin: height * 0.25
                        anchors.bottom: parent.bottom

                        text: model.text
                        font.weight: Font.DemiBold
                        verticalAlignment: Text.AlignVCenter
                        wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                    }

                    states: State {
                        name: "clicked"
                        PropertyChanges {
                            target: itemContatiner
                            color: "lightgray"
                        }
                    }

                    transitions: Transition {
                        ColorAnimation {
                            duration: 100
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        propagateComposedEvents: true
                        onHoveredChanged: {
                            if (containsMouse) {
                                itemContatiner.state = "clicked"
                            } else {
                                itemContatiner.state = ""
                            }
                        }
                        onClicked: {
                            topItem.itemClicked(model.qmlfile)
                            console.log(model.name + " clicked: loading " + model.qmlfile)
                        }
                    }
                }
            }
        }

    }
}

//} // ApplicationWindow

