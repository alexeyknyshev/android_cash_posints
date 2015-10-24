import QtQuick 2.0
import QtQuick.Dialogs 1.2

MessageDialog {
    visible: false
    title: qsTr("Определение местоположения отключено")

    text: qsTr('Приложение не может определить, где вы находитесь. ' +
          'Включите функцию "Моё местоположение"')

    icon: StandardIcon.Information

    standardButtons: StandardButton.Close
}

