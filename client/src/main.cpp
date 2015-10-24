#include "banklistsqlmodel.h"
#include "townlistsqlmodel.h"
#include "serverapi.h"

#include <QApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QFile>
#include <QDebug>
#include <QTableView>

QStringList getSqlQuery(const QString &queryFileName)
{
    QFile queryFile(queryFileName);
    if (!queryFile.open(QFile::ReadOnly | QFile::Text))
    {
        QTextStream(stderr) << "Cannot open " << queryFileName << " file" << endl;
        return QStringList();
    }
    QString queryStr = queryFile.readAll();
    return queryStr.split(";", QString::SkipEmptyParts);
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setAttribute(Qt::AA_SynthesizeMouseForUnhandledTouchEvents, false);
    app.setAttribute(Qt::AA_SynthesizeTouchForUnhandledMouseEvents, false);

    QQmlApplicationEngine engine;

    engine.addImportPath("qrc:/ui");

    // bank list db
    const QString banksConnName = "banks";
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", banksConnName);
    db.setDatabaseName(":memory:");
    if (!db.open())
    {
        qFatal("Cannot create inmem database. Abort.");
        return 1;
    }

    db.transaction();
    db.exec("CREATE TABLE banks (id integer primary key, name text, licence integer, name_tr text, town text, rating integer, name_tr_alt text, tel text)");
    db.exec("CREATE TABLE towns (id integer primary key, name text, name_tr text, region_id integer, regional_center integer)");
    db.exec("CREATE TABLE regions (id integer primary key, name text)");
    db.commit();

    ServerApi *api = new ServerApi("localhost", 8080);

    BankListSqlModel *bankListModel = new BankListSqlModel(banksConnName, api);
    TownListSqlModel *townListModel = new TownListSqlModel(banksConnName, api);

    bankListModel->updateFromServer();
    townListModel->updateFromServer();

    engine.rootContext()->setContextProperty("bankListModel", bankListModel);
    engine.rootContext()->setContextProperty("townListModel", townListModel);
    engine.load(QUrl(QStringLiteral("qrc:/ui/main.qml")));

    const int exitStatus = app.exec();

    delete townListModel;
    delete bankListModel;

    delete api;

    db.close();

    return exitStatus;
}
