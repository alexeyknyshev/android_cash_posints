#include "serverapi.h"

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>

#include <QtCore/QJsonDocument>

ServerApi::ServerApi(const QString &host, int port, QIODevice *sslCertSource, QObject *parent)
    : QObject(parent),
      mNetworkMgr(nullptr),
      mSslConfig(nullptr)
{
    // use secure connection
    if (sslCertSource) {
        _init(host, port, QSslCertificate(sslCertSource));
    } else {
        _init(host, port, QSslCertificate());
    }
}

ServerApi::ServerApi(const QString &host, int port, const QByteArray &sslCertData, QObject *parent)
    : QObject(parent),
      mNetworkMgr(nullptr),
      mSslConfig(nullptr)
{
    _init(host, port, QSslCertificate(sslCertData));
}

void ServerApi::setHost(const QString &host)
{
    mSrvUrl.setHost(host);
}

QString ServerApi::getHost() const
{
    return mSrvUrl.host();
}

void ServerApi::setPort(int port)
{
    mSrvUrl.setPort(port);
}

int ServerApi::getPort() const
{
    return mSrvUrl.port();
}

qint64 ServerApi::uniqueRequestId() const
{
    if (std::numeric_limits<qint64>::max() != mNextUniqueId) {
        return mNextUniqueId++;
    } else {
        mNextUniqueId = 1;
        return mNextUniqueId;
    }
}

void ServerApi::setCallbacksExpireTime(quint32 msec)
{
    mCallbacksExpiteTime = msec;
}

quint32 ServerApi::getCallbacksExpireTime() const
{
    return mCallbacksExpiteTime;
}

qint64 ServerApi::sendRequest(QString path, QJsonObject data, ServerApi::Callback callback)
{
    _eraseExpiredCallbacks();

    qint64 requestId = uniqueRequestId();
    mCallbacks.insert(std::make_pair(requestId, ExpCallback(QDateTime::currentDateTime(),
                                                            callback)));

    QUrl requestUrl(mSrvUrl);
    requestUrl.setPath(path);

    QNetworkRequest req;
    req.setUrl(requestUrl);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json; charset=utf-8");
    req.setRawHeader(QByteArray("Id"), QString::number(requestId).toUtf8());

    if (mSslConfig) {
        req.setSslConfiguration(*mSslConfig);
    }

    if (data.isEmpty()) {
        mNetworkMgr->get(req);
    } else {
        mNetworkMgr->post(req, QJsonDocument(data).toJson(QJsonDocument::Compact));
    }

    return requestId;
}

void ServerApi::update()
{
    _eraseExpiredCallbacks();
}

static ServerApi::HttpStatusCode getStatusCode(QNetworkReply *rep)
{
    bool convertOk = false;
    int status = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(&convertOk);
    if (convertOk) {
        return (ServerApi::HttpStatusCode)status;
    }
    return ServerApi::HSC_ServerError;
}

void ServerApi::onResponseReceived(QNetworkReply *rep)
{
    _eraseExpiredCallbacks();

    if (rep->error() == QNetworkReply::NoError) {
        bool ok = false;
        qint64 requestId = rep->rawHeader(QByteArray("Id")).toLongLong(&ok);
        const auto it = mCallbacks.find(requestId);
        if (it != mCallbacks.cend()) {
            Callback &callback = it->second.callback;
            callback(getStatusCode(rep),
                     rep->readAll(),
                     false);
            mCallbacks.erase(it);
        } else {
            qWarning() << "Unknown request id: " << requestId;
        }
    } else {

    }
}

void ServerApi::_eraseExpiredCallbacks()
{
    QDateTime now = QDateTime::currentDateTime();
    auto it = mCallbacks.begin();
    while (it != mCallbacks.end()) {
        if (qAbs(it->second.dt.msecsTo(now)) > static_cast<qint64>(getCallbacksExpireTime())) {
            qint64 requestId = it->first;
            Callback &callback = it->second.callback;
            callback(HSC_RequestTimeout, QByteArray(), true);
            mCallbacks.erase(it);
            emit requestTimedout(requestId);
            return;
        }
        ++it;
    }
}

void ServerApi::_init(const QString &host, int port, const QSslCertificate &cert)
{
    mNextUniqueId = 1;

    if (!cert.isNull()) {
        mSslConfig = new QSslConfiguration;
        mSslConfig->setCaCertificates({ cert });
        mSslConfig->setProtocol(QSsl::TlsV1_2);
    }

    setCallbacksExpireTime(1000);
    setHost(host);
    setPort(port);
    mNetworkMgr = new QNetworkAccessManager(this);
    connect(mNetworkMgr, SIGNAL(finished(QNetworkReply*)), this, SLOT(onResponseReceived(QNetworkReply*)));

    if (cert.isNull()) {
        mSrvUrl.setScheme("http");
    } else {
        mSrvUrl.setScheme("https");
    }
}
