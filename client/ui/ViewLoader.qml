import QtQuick 2.0

Rectangle {
    anchors.fill: parent

    function setView(qmlfile) {
        loader.source = qmlfile
    }

    Loader {
        anchors.fill: parent
        id: loader
        asynchronous: true
    }
}

