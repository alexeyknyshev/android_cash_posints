#include <QtTest/QtTest>

#include <QtNetwork/QSslSocket>

#include "../src/serverapi.h"

bool floatCompare(float a, float b)
{
    return qAbs(a - b) < 0.0001f;
}

class ServerApiTest : public QObject
{
    Q_OBJECT

private:
    struct Response {
        QVariantMap data;
        bool ok;
    };

    Response sendRequest(const QString &path, const QJsonObject &reqData, bool secure,
                         int callbackExpireTime = 1000, int updateInterval = 500);

private slots:
    void initTestCase();
    void cleanupTestCase();

    void testUserCreateRequest();
    void testTownsListRequest();
    void testTownByIdRequest();
    void testCashpointRequest();
};

void ServerApiTest::initTestCase()
{
}

void ServerApiTest::cleanupTestCase()
{
}

void ServerApiTest::testUserCreateRequest()
{
    const QString path = "/user";
    QJsonObject req
    {
        {"login", "testUser"},
        {"password", "testPassword"}
    };

    const Response res = sendRequest(path, req, false, 2000);

    QCOMPARE(res.ok, true);
}

void ServerApiTest::testTownsListRequest()
{
    QBENCHMARK {
        const QString path = "/towns";
        const Response res = sendRequest(path, QJsonObject(), false);

        QVariantList list = res.data["towns"].toList();
        foreach (const QVariant &val, list) {
            QCOMPARE(val.type(), QVariant::Double); // json numeric type is double
        }

        static const int expectedTownsCount = 10000;
        QVERIFY2(list.size() > expectedTownsCount, "Towns count is not expected to be less");
    }
}

void ServerApiTest::testTownByIdRequest()
{
    const int townId = 32;
    const QString path = "/town/" + QString::number(townId);

    const Response res = sendRequest(path, QJsonObject(), false);

    QCOMPARE(res.ok, true);
    {
        QCOMPARE(res.data["id"].toInt(),         townId);
        QCOMPARE(res.data["name"].toString(),    QString("Волоколамск"));
        QCOMPARE(res.data["name_tr"].toString(), QString("Volokolamsk"));
        QCOMPARE(res.data["zoom"].toInt(),       12);
    }
}

void ServerApiTest::testCashpointRequest()
{
    const int cpId = 6271738;
    const QString path = "/cashpoint/" + QString::number(cpId);

    const Response res = sendRequest(path, QJsonObject(), false);

    QCOMPARE(res.ok, true);
    {
        QCOMPARE(res.data["id"].toInt(),      cpId);
        QCOMPARE(res.data["type"].toString(), QString("atm"));
        QCOMPARE(res.data["bank_id"].toInt(), 3425);
        QCOMPARE(res.data["town_id"].toInt(), 4);
        QVERIFY(floatCompare(res.data["longitude"].toDouble(), 37.699253076057));
        QVERIFY(floatCompare(res.data["latitude"].toDouble(), 55.7949921030773));
//        QCOMPARE(res.data["address"].toString(), QString("г.Москва, ул. Стромынка, д. 21 корп. 1"));
        QCOMPARE(res.data["address_comment"].toString(), QString("Управление социальной защиты населения района «Преображенский»"));
        QCOMPARE(res.data["metro_name"].toString(), QString("Преображенская площадь"));
        QCOMPARE(res.data["free_access"].toInt(), 1);
        QCOMPARE(res.data["main_office"].toInt(), 0);
        QCOMPARE(res.data["without_weekend"].toInt(), 1);
        QCOMPARE(res.data["round_the_clock"].toInt(), 0);
        QCOMPARE(res.data["works_as_shop"].toInt(), 1);
        QCOMPARE(res.data["rub"].toInt(), 1);
        QCOMPARE(res.data["usd"].toInt(), 0);
        QCOMPARE(res.data["eur"].toInt(), 0);
        QCOMPARE(res.data["cash_in"].toInt(), 0);
    }
}

/// ===============================================================

ServerApiTest::Response ServerApiTest::sendRequest(const QString &path, const QJsonObject &reqData, bool secure,
                                                   int callbackExpireTime, int updateInterval)
{
    /// TODO: secure connection
    Q_UNUSED(secure)
//    QFile certFile(":/data/cert.pem");
//    QVERIFY2(certFile.open(QIODevice::ReadOnly), "Cannot open cert file");
//    QSslSocket::addDefaultCaCertificate(QSslCertificate(&certFile, QSsl::Pem));

    Response response;

    ServerApi api("127.0.0.1", 8080);
//    ServerApi api("127.0.0.1", 8081, &certFile);
    {
        QEventLoop loop;
        connect(&api, SIGNAL(requestTimedout(qint64)), &loop, SLOT(quit()));
        connect(&api, SIGNAL(responseReceived(qint64)), &loop, SLOT(quit()));

        QTimer *apiUpdateTimer = new QTimer(&api);
        connect(apiUpdateTimer, SIGNAL(timeout()), &api, SLOT(update()));

        api.setCallbacksExpireTime(callbackExpireTime);
        api.sendRequest(path, reqData,
        [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut)
        {
            response.ok = false;
            if (!timeOut) {
                if (code == ServerApi::HSC_Ok) {
                    response.ok = true;
                    QJsonDocument jsonDoc = QJsonDocument::fromJson(data);
                    response.data = jsonDoc.object().toVariantMap();
                } else {
                    qWarning() << "Request status code: " << code;
                }
            } else {
                qWarning() << "Request timed out";
            }
            loop.quit();
        });

        apiUpdateTimer->start(updateInterval);

        loop.exec();
    }

    return response;
}

QTEST_MAIN(ServerApiTest)
#include "ts_serverapi.moc"
