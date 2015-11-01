#ifndef SERVERAPI_H
#define SERVERAPI_H

#include <functional>

#include <QtCore/QObject>
#include <QtCore/QUrl>
#include <QtCore/QDateTime>
#include <QtCore/QJsonObject>
#include <QtCore/QMap>

class QNetworkAccessManager;
class QNetworkReply;
class QSslConfiguration;
class QSslCertificate;
class QIODevice;

class ServerApi : public QObject
{
    Q_OBJECT

public:
    ServerApi(const QString &host, int port,
              QIODevice *sslCertSource, QObject *parent = nullptr);

    ServerApi(const QString &host, int port,
              const QByteArray &sslCertData = QByteArray(), QObject *parent = nullptr);

    enum HttpStatusCode {
        HSC_Ok = 200,
        HSC_BadRequest = 400,
        HSC_Unauthorized = 401,
        HSC_NotFound = 404,
        HSC_RequestTimeout = 408,
        HSC_Conflict = 409,
        HSC_ServerError = 500,
        HSC_NotImplemented = 501
    };

    void setHost(const QString &host);
    void setPort(int port);

    QString getHost() const;
    int getPort() const;

    qint64 uniqueRequestId() const;

    void setCallbacksExpireTime(quint32 msec);
    quint32 getCallbacksExpireTime() const;

    typedef std::function<void(HttpStatusCode code, const QByteArray &data, bool timeOut)> Callback;

    qint64 sendRequest(QString path, QJsonObject data, ServerApi::Callback callback);

signals:
    void responseReceived(qint64 requestId);
    void requestTimedout(qint64 requestId);

    void pong(bool ok);

public slots:
    void postRequest(QString path, QJsonObject data, ServerApi::Callback Callback);
    void update();

    void ping();

private slots:
    void onResponseReceived(QNetworkReply *);

private:
    void emitPong(bool ok);

    mutable qint64 mNextUniqueId;
    QUrl mSrvUrl;
    QNetworkAccessManager *mNetworkMgr;
    QSslConfiguration *mSslConfig;

    struct ExpCallback {
        ExpCallback(const QDateTime &dt_, const ServerApi::Callback &callback_)
            : dt(dt_), callback(callback_)
        { }

        QDateTime dt;
        Callback callback;
    };

    QMap<qint64, ExpCallback> mCallbacks;

    void _eraseExpiredCallbacks();
    void _init(const QString &host, int port, const QSslCertificate &cert);

    quint32 mCallbacksExpiteTime;
};

#endif // SERVERAPI_H
