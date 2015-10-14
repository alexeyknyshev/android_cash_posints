#include <QtCore/QUrl>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkAccessManager>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>
#include <QtCore/QTimer>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    QUrl url("http://127.0.0.1:8080/town/4");
//    QUrl url("http://127.0.0.1:8080/town/141/bank/322/cashpoints");
    QNetworkRequest req;
    req.setUrl(url);
    req.setRawHeader(QByteArray("Id"), QString::number(1).toUtf8());
    QNetworkAccessManager *mgr = new QNetworkAccessManager(&app);

    const QDateTime now = QDateTime::currentDateTime();

    QNetworkReply *reply = mgr->get(req);
    QObject::connect(reply, &QNetworkReply::readyRead, [&app, reply, &now] {
        qint64 deltaMsec = qAbs(QDateTime::currentDateTime().msecsTo(now));
        qDebug() << "request round-trip: " << deltaMsec << "ms";

        QByteArray data = reply->readAll();
        QJsonDocument jsonDocument = QJsonDocument::fromJson(data);
        QVariantMap keyValuePairs = jsonDocument.object().toVariantMap();

//        qDebug() << data;


        QString text;
        for (auto it = keyValuePairs.begin(); it != keyValuePairs.end(); ++it) {
//            qDebug() << it.key() << ": " << it.value();
            text += it.key() + ":\t" + it.value().toString() + "\n";
        }
        QMessageBox::information(nullptr, "json reply", text);
    });

    QTimer *timer = new QTimer(&app);
    timer->setSingleShot(true);
    QObject::connect(timer, &QTimer::timeout, [&app] {
        app.quit();
    });

    timer->start(1000);

    app.exec();

    return 0;
}
