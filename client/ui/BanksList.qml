import QtQuick 2.4
import QtQuick.Controls 1.3
import QtGraphicalEffects 1.0

//ApplicationWindow {
//    visible: true
//    width: 800
//    height: 600
//    visibility: "FullScreen"

Rectangle {
    id: topRect
    anchors.fill: parent
    color: "#EDEDED"

    onParentChanged: {
        bankListModel.setFilter("")
    }

    Rectangle {
        id: bankFilterEditContainer

        z: bankListView.z + 1

        anchors.top: parent.top
        anchors.topMargin: anchors.leftMargin
        anchors.left: parent.left
        anchors.leftMargin: parent.width * 0.02
        anchors.right: parent.right
        anchors.rightMargin: anchors.leftMargin
        anchors.bottomMargin: anchors.leftMargin

        radius: height / 20
        height: bankFilterEdit.contentHeight * 2

        TextInput {
            id: bankFilterEdit

            z: bankListView.z + 1

            anchors.top: parent.top
            anchors.topMargin: bankFilterEdit.contentHeight * 0.5
            anchors.left: upperSwitcher.right
            anchors.leftMargin: bankFilterEdit.contentHeight * 0.5
            anchors.right: clearButton.left
            anchors.rightMargin: bankFilterEdit.contentHeight * 0.5
            anchors.bottomMargin: bankFilterEdit.contentHeight * 0.5
            anchors.bottom: parent.bottom

            echoMode: TextInput.Normal

            font.pixelSize: Math.max(topRect.height, topRect.width) / (15 * 3) > 18 ?
                            Math.max(topRect.height, topRect.width) / (15 * 3) : 18

            property bool isUserTextShowed: false
            property string placeHolderText: qsTr("Банк, номер лицезии, номер тел...")
            property string userText: ""

            wrapMode: Text.NoWrap

            Component.onCompleted: {
                text = placeHolderText
                color = "lightgray"
            }

            onFocusChanged: {
                if (bankFilterEdit.focus) {
                    text = userText
                    color = "black"
                    isUserTextShowed = true
                } else {
                    userText = text
                    if (userText == "") {
                        text = placeHolderText
                        color = "lightgray"
                        isUserTextShowed = false
                    }
                }
            }

            function setFirstLetterUpper(upper)
            {
                if (upper && text != "") {
                    text = text.charAt(0).toUpperCase() + text.slice(1)
                }
            }

            onTextChanged: {
                setFirstLetterUpper(upperSwitcher.state == "enabled")
            }

            onDisplayTextChanged: {
                if (displayText === "" || displayText === placeHolderText) {
                    bankListModel.setFilter("")
                } else {
                    bankListModel.setFilter(displayText)
                }
            }
        } // TextInput

        UpperSwitcher {
            id: upperSwitcher

            anchors.left: parent.left
            anchors.leftMargin: bankFilterEdit.contentHeight * 0.2
            anchors.bottom: parent.bottom
            anchors.bottomMargin: bankFilterEdit.contentHeight * 0.2
            anchors.top: parent.top
            anchors.topMargin: bankFilterEdit.contentHeight * 0.3
            width: height

            onEnabledChanged: {
                bankFilterEdit.setFirstLetterUpper(isEnabled)
            }

            onParentChanged: {
                state = "enabled"
            }
        }

        Rectangle {
            id: clearButton
            color: "transparent"
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.topMargin: bankFilterEdit.topMargin
            anchors.bottom: parent.bottom
            anchors.bottomMargin: bankFilterEdit.bottomMargin
            width: height
            opacity: bankFilterEdit.isUserTextShowed && bankFilterEdit.displayText != "" ? 1.0 : 0.0

            Behavior on opacity {
                NumberAnimation { duration: 100 }
            }

            Rectangle {
                anchors.centerIn: parent
                height: parent.width * 0.05
                width: parent.width * 0.5
                color: "gray"
                rotation: 45
            }
            Rectangle {
                anchors.centerIn: parent
                height: parent.width * 0.05
                width: parent.width * 0.5
                color: "gray"
                rotation: -45
            }

            states: State {
                name: "pressed"
                PropertyChanges {
                    target: clearButton
                    color: "lightgray"
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    bankFilterEdit.userText = ""
                    bankFilterEdit.text = ""
                }

                onHoveredChanged: {
                    if (containsMouse) {
                        parent.state = "pressed"
                    } else {
                        parent.state = ""
                    }
                }
            }
        }
    }

    RectangularGlow {
        anchors.fill: bankFilterEditContainer
        glowRadius: bankFilterEditContainer.height / 10
        spread: 0.2
        color: "#11000055"
        cornerRadius: glowRadius
    }

    Rectangle {
        anchors.top: bankFilterEditContainer.bottom
        anchors.topMargin: bankFilterEditContainer.anchors.topMargin
        anchors.left: parent.left
        anchors.leftMargin: bankFilterEditContainer.anchors.leftMargin
        anchors.right: parent.right
        anchors.rightMargin: bankFilterEditContainer.anchors.rightMargin
        anchors.bottom: parent.bottom
        anchors.bottomMargin: bankFilterEditContainer.anchors.bottomMargin

        RectangularGlow {
            anchors.fill: bankListViewContainer
            glowRadius: bankFilterEditContainer.height / 10
            spread: 0.2
            color: "#11000055"
            cornerRadius: glowRadius
        }

        ScrollView {
            id: bankListViewContainer
            anchors.fill: parent
            verticalScrollBarPolicy: Qt.ScrollBarAlwaysOff

            ListView {
                id: bankListView
                anchors.fill: parent
                snapMode: ListView.SnapToItem

                model: bankListModel
                delegate: Rectangle {
                    id: itemContatiner
                    height: (itemText.contentHeight * (itemText.lineCount + 2) / itemText.lineCount)
                    width: parent.width
                    Rectangle {
                        anchors.top: parent.top
                        color: "lightgray"
                        height: 1
                        width: parent.width
                    }

                    Image {
                        id: itemImage
                        source: "../ico/ico/logo/" + model.bank_name_tr_alt + ".svg"
                        smooth: true
                        fillMode: Image.PreserveAspectFit
                        anchors.left: parent.left
                        anchors.leftMargin: bankFilterEdit.anchors.leftMargin
                        anchors.top: parent.top
                        anchors.topMargin: bankFilterEdit.anchors.topMargin
//                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: bankFilterEdit.anchors.bottomMargin
                        height: bankListView.height / 15
                        width: height
                    }

                    Label {
                        id: itemText

                        anchors.verticalCenter: parent.verticalCenter

                        anchors.left: itemImage.right
                        //anchors.right: itemTelNumber.left
                        anchors.right: parent.right
                        anchors.rightMargin: bankFilterEdit.anchors.rightMargin
                        anchors.leftMargin: bankFilterEdit.anchors.leftMargin

                        verticalAlignment: Text.AlignVCenter
                        text: model.bank_name.replace(bankFilterEdit.displayText,
                                                      '<b>' + bankFilterEdit.displayText +
                                                      '</b>')
                        textFormat: Text.StyledText
                        wrapMode: Text.WordWrap
                        font.pixelSize: Math.max(topRect.height, topRect.height) / (15 * 3) > 18 ?
                                        Math.max(topRect.height, topRect.height) / (15 * 3) : 18
                    }

                    /*Label {
                        id: itemTelNumber

                        anchors.verticalCenter: parent.verticalCenter

                        //anchors.left: itemText.right
                        anchors.right: parent.right
                        anchors.leftMargin: bankFilterEdit.anchors.leftMargin
                        anchors.rightMargin: bankFilterEdit.anchors.rightMargin

                        verticalAlignment: Text.AlignRight
                        text: model.bank_tel.replace(bankFilterEdit.displayText,
                                                    '<b>' + bankFilterEdit.displayText +
                                                    '</b>')
                        textFormat: Text.StyledText
                        wrapMode: Text.NoWrap
                        font.pixelSize: Math.max(topRect.height, topRect.width) / (15 * 3) > 18 ?
                                        Math.max(topRect.height, topRect.width) / (15 * 3) : 18
                    }*/

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
                        onHoveredChanged: {
                            if (containsMouse) {
                                itemContatiner.state = "clicked"
                            } else {
                                itemContatiner.state = ""
                            }
                        }
                        onClicked: {
                            console.log("selected bank: " + model.bank_name)
                        }
                    }
                }
            }
        } // Rectangle
    }
}
//} // ApplicationWindow
