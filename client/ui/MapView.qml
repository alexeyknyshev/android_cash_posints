import QtQuick 2.4
import QtQuick.Controls 1.3
import QtLocation 5.3
import QtPositioning 5.3
import QtSensors 5.3
import QtGraphicalEffects 1.0

Item {
    id: topView
    width: 480
    height: 800
    visible: true

    focus: true

    property bool active: true

    signal clicked()
    signal menuClicked()

    Keys.onEscapePressed: Qt.quit()
    Keys.onPressed: {
        if (event.key === Qt.Key_Plus) {
            map.zoom(map.zoomLevel + 1)
        } else if (event.key === Qt.Key_Minus) {
            map.zoom(map.zoomLevel - 1)
        }
    }

    Plugin {
        id: mapPlugin
        name: "osm"
    }

    function aboutToClose() {
        if (holdDialog.visible) {
            holdDialog.hide()
            return false
        }
        return true
    }

    PositionSource {
        id: positionSource
        updateInterval: 200
        preferredPositioningMethods: PositionSource.AllPositioningMethods
        property bool needUpdate: false
        property MapQuickItem me: null
        property bool locationAvaliable: false
        onPositionChanged: {
            locationAvaliable = true
            if (position.coordinate.isValid && needUpdate) {
                needUpdate = false
                map.moveToCoord(position.coordinate)
                var expectedZoomLevel = map.minimumZoomLevel + (map.maximumZoomLevel - map.minimumZoomLevel) * 0.9
                if (expectedZoomLevel >= map.zoomLevel) {
                    map.zoom(map.minimumZoomLevel + (map.maximumZoomLevel - map.minimumZoomLevel) * 0.9)
                }

                if (me == null) {
                    var mapMeMarkComponent = Qt.createComponent("MapMeMark.qml")
                    if (mapMeMarkComponent.status == Component.Ready) {
                        me = mapMeMarkComponent.createObject(map)
                    }
                }
                me.coordinate = position.coordinate
                map.addMapItem(me)

                findMeButtonRotationAnim.stop()
                findMeButtonRotationAnimBack.start()
            }
        }

        onSourceErrorChanged: {
            if (sourceError === PositionSource.ClosedError) {
                locationAvaliable = false
                console.error("position source is disabled")
            } else if (sourceError === PositionSource.NoError) {
                locationAvaliable = true
            }
        }

        function forceUpdate() {
            needUpdate = true
            update()
        }

        function debugPrintSupportedPositioningMethods() {
            if (supportedPositioningMethods == PositionSource.AllPositioningMethods) {
                console.log("All pos methods")
                return
            }
            if (supportedPositioningMethods & PositionSource.SatellitePositioningMethods) {
                console.log("Sat pos methods")
            }
            if (supportedPositioningMethods & PositionSource.NonSatellitePositioningMethods) {
                console.log("Network pos methods")
            }
            if (supportedPositioningMethods & PositionSource.NoPositioningMethods) {
                console.log("No pos methods")
            }
        }
    }

    EnableLocServiceDialog {
        id: enableLocServiceDialog
        onVisibilityChanged: {
            console.log("dialog showed")
        }
    }

    MapHoldDialog
    {
        id: holdDialog
        visible: false
        z: parent.z + 1
    }

    Map {
        id: map
        anchors.fill: parent
        plugin: mapPlugin;
        center {
            id: center
            latitude: coordLatitude
            longitude: coordLongitude
        }
        zoomLevel: 13
        maximumZoomLevel: 50

        property bool panActive: false
        property real panLastX: 0
        property real panLastY: 0

        property real targetZoomLevel: 13
        property real coordLatitude: 55.7522200
        property real coordLongitude: 37.6155600

        gesture.flickDeceleration: 3000
        gesture.enabled: false
        gesture.activeGestures: MapGestureArea.FlickGesture | MapGestureArea.PanGesture

        property bool zooming: false

        PropertyAnimation {
            id: zoomLevelAnim
            target: map
            property: "zoomLevel"
            to: map.targetZoomLevel
            duration: 300
            easing.type: Easing.InOutQuad
        }


        function zoom(zoomFactor) {
            if (zoomFactor > maximumZoomLevel) {
                targetZoomLevel = maximumZoomLevel
            } else if (zoomFactor < minimumZoomLevel) {
                targetZoomLevel = minimumZoomLevel
            } else {
                targetZoomLevel = zoomFactor
            }

            if (zoomLevelAnim.running) {
                zoomLevelAnim.stop()
            }

            zoomLevelAnim.start()
        }

        function moveToCoord(coord) {
            console.warn("Coordinate:", coord.latitude, coord.longitude);
            map.center = coord
        }

        function findMe() {
            if (!positionSource.valid) {
                console.log("position source is invalid!")
                enableLocServiceDialog.open()
            }

            positionSource.debugPrintSupportedPositioningMethods()
            if (positionSource.supportedPositioningMethods ===
                    PositionSource.NoPositioningMethods)
            {
                return
            }

            if (!positionSource.active) {
                positionSource.start()
            }

            positionSource.forceUpdate()

            if (!positionSource.locationAvaliable) {
                enableLocServiceDialog.open()
            }
        }

        PinchArea {
            anchors.fill: parent

            property real oldZoom: 13

            onParentChanged: oldZoom = parent.zoomLevel

            onPinchStarted: {
                if (topView.active) {
                    console.log("pinch started")
                    oldZoom = map.zoomLevel
                }
            }

            onPinchUpdated: {
                if (topView.active) {
                    console.log("pinch")
                    console.log("scale: " + pinch.scale)
                    map.zoomLevel = oldZoom + Math.log(pinch.scale) / Math.log(2)
                }
            }

            MouseArea {
                id: mapMouseArea
                anchors.fill: parent
                z: parent.z + 1

                onClicked: {
                    topView.clicked()

                    if (!topView.active)
                        return

                    if (parent.zooming)
                    {
                        parent.zooming = false
                        return
                    }

                    if (!holdDialog.visible) {
                        console.log(mouseX, mouseY)
                        console.log(map.toCoordinate(Qt.point(mouseX, mouseY)))
                        console.log(map.center)
//                        console.log("Map clicked!")
                    } else {
                        holdDialog.hide()
                    }
                }
//                onPressAndHold: {
//                    if (!map.zooming) {
//                        console.log("Hoooold...")
//                        holdDialog.show()
//                    }
//                }
                onDoubleClicked: {
                    if (!topView.active)
                        return
//                    console.log("double click!")

                    var coord = map.toCoordinate(Qt.point(mouseX, mouseY))

                    // prevent flicker near center
                    if (Math.abs(mouseX - width  / 2) / width  > 0.05 ||
                        Math.abs(mouseY - height / 2) / height > 0.05)
                    {
                        map.moveToCoord(coord)
                    }

                    map.zoom(map.zoomLevel + 1)
                }
                onPositionChanged: {
                    if (!topView.active)
                        return

                    if (!map.panActive) {
                        map.panActive = true
                        map.panLastX = mouseX
                        map.panLastY = mouseY
                        return
                    }

                    var deltaX = mouseX - map.panLastX
                    var deltaY = mouseY - map.panLastY

//                    console.log("deltaX: " + deltaX)
//                    console.log("deltaY: " + deltaY)

                    var coord = map.toCoordinate(Qt.point(width / 2 - deltaX, height / 2 - deltaY))

                    map.center = coord

                    map.panLastX = mouseX
                    map.panLastY = mouseY

//                    console.log("mouse moved")
                }

                onReleased: {
                    map.panActive = false
//                    console.log("mouse released")
                }
            }
        }



        Rectangle {
            z: parent.z + 1
            id: zoomOutButton
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.rightMargin: height * 0.25
            height: Math.min(Math.max(parent.width, parent.height) * 0.1, 160)
            width: height
            radius: width * 0.5
            color: "#3295BA"
            opacity: 0.9

            Behavior on scale {
                NumberAnimation { duration: 100 }
            }

            Rectangle {
                anchors.centerIn: parent
                width: parent.width * 0.3
                height: parent.height * 0.05
                radius: height * 0.1
            }

            MouseArea {
                anchors.fill: parent
                onClicked: if (topView.active) map.zoom(map.zoomLevel - 1)
                onPressed: if (topView.active) parent.scale = 0.9
                onReleased: parent.scale = 1.0
            }

        }


        Rectangle {
            z: parent.z + 1
            id: zoomInButton
            anchors.top: zoomOutButton.bottom
            anchors.topMargin: height * 0.25
            anchors.right: parent.right
            anchors.rightMargin: height * 0.25
            height: Math.min(Math.max(parent.width, parent.height) * 0.1, 160)
            width: height
            radius: width * 0.5
            color: "#D94336"
            opacity: 0.9

            Behavior on scale {
                NumberAnimation { duration: 100 }
            }

            Rectangle {
                anchors.centerIn: parent
                width: parent.width * 0.05
                height: parent.height * 0.3
                radius: width * 0.1
            }


            Rectangle {
                anchors.centerIn: parent
                width: parent.width * 0.3
                height: parent.height * 0.05
                radius: height * 0.1
            }

            MouseArea {
                anchors.fill: parent
                onClicked: if (topView.active) map.zoom(map.zoomLevel + 1)
                onPressed: if (topView.active) parent.scale = 0.9
                onReleased: parent.scale = 1.0
            }
        }

//        InnerShadow {
//            anchors.fill: zoomOutButton
//            radius: 128.0
//                    samples: 16
//                    horizontalOffset: -10
//                    verticalOffset: -10
//                    color: "#b0000000"
//                    source: zoomOutButton
//        }

        Rectangle {
            id: findMeButton
            z: parent.z + 1
            anchors.left: parent.left
            anchors.leftMargin: height * 0.25
            anchors.verticalCenter: parent.verticalCenter
            anchors.margins: 1
            height: Math.min(Math.max(parent.width, parent.height) * 0.1, 160)
            width: height
            radius: width * 0.5
            opacity: 0.9
            color: "#3295BA"

            property bool activated: false

            SequentialAnimation {
                id: findMeButtonRotationAnim
                running: false
                loops: 3
                RotationAnimation {
                    target: findMeButton
                    to: 180
                    duration: 1500
                    easing.type: Easing.InOutCubic
                }
                RotationAnimation {
                    target: findMeButton
                    to: 0
                    duration: 1500
                    easing.type: Easing.InOutCubic
                }
            }

            RotationAnimation {
                id: findMeButtonRotationAnimBack
                running: false
                target: findMeButton
                to: 0
                duration: 1500 * (findMeButton.rotation / 180)
            }

            Behavior on scale {
                NumberAnimation { duration: 100 }
            }


            Rectangle {
                anchors.centerIn: parent
                width: parent.width * 0.5
                height: parent.height * 0.04
                color: "white"
            }

            Rectangle {
                anchors.centerIn: parent
                width: parent.height * 0.04
                height: parent.width * 0.5
                color: "white"
            }

            Rectangle {
                anchors.centerIn: parent
                width: parent.width * 0.4
                height: width
                color: "white"
                radius: width * 0.4

                Rectangle {
                    anchors.centerIn: parent
                    width: parent.width * 0.8
                    height: width
                    radius: width * 0.4
                    color: findMeButton.color

                    Rectangle {
                        anchors.centerIn: parent
                        width: parent.width * 0.5
                        height: width
                        radius: width * 0.5
                        color: "#D94336"
                    }
                }
            }

//            property bool scaleAnimated: false
/*
            states: [
                State {
                    name: "animated_out"
                    PropertyChanges {
                        target: findMeButton
                        scale: 0.8
                    }
                    onCompleted: findMeButton.state = "animated_in"
                },
                State {
                    name: "animated_in"
                    PropertyChanges {
                        target: findMeButton
                        scale: 1.0
                    }
                    onCompleted: {
                        if (findMeButton.scaleAnimated) {
                            findMeButton.state = "animated_out"
                        } else {
                            findMeButton.state = ""
                        }
                    }
                 }
             ]

             transitions: Transition {
                 ScaleAnimator {
                     duration: 2000
                 }
             }*/

             MouseArea {
                 anchors.fill: parent
                 onClicked: {
                     if (!topView.active)
                         return

                     map.findMe()
                     if (positionSource.locationAvaliable) {
                        findMeButtonRotationAnim.start()
                     }
                 }
                 onPressed: parent.scale = 0.9
                 onReleased: parent.scale = 1.0
             }
        }
    }

    Rectangle {
        id: searchLineEditContainer

        z: parent.z + 2

        anchors.top: parent.top
        anchors.topMargin: anchors.leftMargin
        anchors.left: parent.left
        anchors.leftMargin: parent.width * 0.02
        anchors.right: parent.right
        anchors.rightMargin: anchors.leftMargin
        anchors.bottomMargin: anchors.leftMargin

        radius: height / 20
        height: searchLineEdit.contentHeight * 2

//        color: "lightgray"

        TextInput {
            id: searchLineEdit

            z: parent.z + 1

            anchors.top: parent.top
            anchors.topMargin: searchLineEdit.contentHeight * 0.5
            anchors.left: menuButton.right
            anchors.leftMargin: searchLineEdit.contentHeight * 0.5
            anchors.right: clearButton.left
            anchors.rightMargin: searchLineEdit.contentHeight * 0.5
            anchors.bottomMargin: searchLineEdit.contentHeight * 0.5
            anchors.bottom: parent.bottom

            echoMode: TextInput.Normal

            font.pixelSize: Math.max(topView.height, topView.width) / (15 * 2) > 18 ?
                            Math.max(topView.height, topView.width) / (15 * 2) : 18

            property bool isUserTextShowed: false
            property string placeHolderText: qsTr("Искать")
            property string userText: ""

            wrapMode: Text.NoWrap

            Component.onCompleted: {
                text = placeHolderText
                color = "lightgray"
            }

            onFocusChanged: {
                if (searchLineEdit.focus) {
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

            onDisplayTextChanged: {
                if (displayText === "" || displayText === placeHolderText) {
                    bankListModel.setFilter("")
                } else {
                    bankListModel.setFilter(displayText)
                }
            }
        } // TextInput

        Rectangle {
            id: menuButton
            z: parent.z + 1

            anchors.left: parent.left
            anchors.leftMargin: searchLineEdit.contentHeight * 0.2
            anchors.bottom: parent.bottom
            anchors.bottomMargin: searchLineEdit.contentHeight * 0.3
            anchors.top: parent.top
            anchors.topMargin: searchLineEdit.contentHeight * 0.3
            width: height

            Rectangle {
                id: menuButtonTopRect
                anchors.top: parent.top
                anchors.topMargin: parent.height * 2 / 9
                anchors.left: parent.left
                anchors.leftMargin: parent.width * 0.2
                height: parent.height / 9
                width: parent.width * 0.6
                color: "gray"
            }

            Rectangle {
                id: menuButtonCenterRect
                anchors.top: menuButtonTopRect.bottom
                anchors.topMargin: parent.height / 9
                anchors.left: parent.left
                anchors.leftMargin: parent.width * 0.2
                height: menuButtonTopRect.height
                width: parent.width * 0.6
                color: "gray"
            }

            Rectangle {
                anchors.top: menuButtonCenterRect.bottom
                anchors.topMargin: parent.height / 9
                anchors.left: parent.left
                anchors.leftMargin: parent.width * 0.2
                height: menuButtonTopRect.height
                width: parent.width * 0.6
                color: "gray"
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    console.log("menu clicked")
                    topView.menuClicked()
                }
            }
        }

        Rectangle {
            id: clearButton
            color: "transparent"
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.topMargin: searchLineEdit.topMargin
            anchors.bottom: parent.bottom
            anchors.bottomMargin: searchLineEdit.bottomMargin
            width: height
            opacity: searchLineEdit.isUserTextShowed && searchLineEdit.displayText != "" ? 1.0 : 0.0

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
                    searchLineEdit.userText = ""
                    searchLineEdit.text = ""
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
        z: searchLineEditContainer.z - 1
        anchors.fill: searchLineEditContainer
        glowRadius: searchLineEditContainer.height / 5
        spread: 0.3
        color: "#11000055"
        cornerRadius: glowRadius
    }
}

