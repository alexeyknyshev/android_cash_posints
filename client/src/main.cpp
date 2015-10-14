#include <QApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QFile>
#include <QDebug>
#include <QTableView>

#include "banklistsqlmodel.h"
#include "townlistsqlmodel.h"

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

    engine.addImportPath("qrc:/");

    // bank list db
    const QString banksConnName = "banks";
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", banksConnName);
    db.setDatabaseName(":memory:");
    if (!db.open())
    {
        qFatal("Cannot create inmem database. Abort.");
        return 1;
    }

    foreach (QString sqlFile, QStringList() << ":/banks.sql" << ":/town.sql")
    {
        QStringList q_list = getSqlQuery(sqlFile);
        db.transaction();
        foreach (QString qStr, q_list)
        {
            db.exec(qStr);
        }
        db.commit();
    }

    BankListSqlModel *bankListModel = new BankListSqlModel(banksConnName);
    TownListSqlModel *townListModel = new TownListSqlModel(banksConnName);

    engine.rootContext()->setContextProperty("bankListModel", bankListModel);
    engine.rootContext()->setContextProperty("townListModel", townListModel);
//    engine.load(QUrl("qrc:/LeftMenu.qml"));
//    engine.load(QUrl(QStringLiteral("qrc:/BanksList.qml")));
//    engine.load(QUrl(QStringLiteral("qrc:/TownList.qml")));
    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));
//    engine.load(QUrl(QStringLiteral("qrc:/UpperSwitcher.qml")));

    const int exitStatus = app.exec();

    delete townListModel;
    delete bankListModel;

    db.close();

    return exitStatus;
}
