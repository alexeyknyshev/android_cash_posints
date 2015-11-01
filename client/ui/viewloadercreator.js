var component;
var viewloader;
var callback;

function createViewLoader(callbackFunc) {
    callback = callbackFunc
    if (component) {
        callback(viewloader)
        return
    }

    component = Qt.createComponent("ViewLoader.qml");
    if (component.status === Component.Ready) {
        finishCreation();
    } else {
        component.statusChanged.connect(finishCreation);
    }
}

function finishCreation() {
    if (component.status === Component.Ready) {
        viewloader = component.createObject(flipable.front, { "anchors.fill": flipable.front });
        if (!viewloader) {
            console.log("Error creating ViewLoader object");
        }
        if (callback) {
            callback(viewloader)
        }
    } else if (component.status === Component.Error) {
        console.log("Error loading component:", component.errorString());
    }
}
