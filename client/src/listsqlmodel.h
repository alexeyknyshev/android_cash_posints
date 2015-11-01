#ifndef LISTSQLMODEL_H
#define LISTSQLMODEL_H

#include <QtGui/QStandardItemModel>

class ServerApi;
class IcoImageProvider;
class QSqlQuery;
class QSettings;

class ListSqlModel : public QStandardItemModel
{
    Q_OBJECT

public:
    ListSqlModel(const QString &connectionName,
                 ServerApi *api,
                 IcoImageProvider *imageProvider,
                 QSettings *settings);

    static QString escapeFilter(QString filter);

signals:
    void serverDataReceived();
    void filterRequest(QString filter);

public slots:
    void setFilter(QString filter);

    void updateFromServer();

protected:
    virtual void setFilterImpl(const QString &filter) = 0;
    virtual void updateFromServerImpl(quint32 leftAttempts) = 0;
    virtual int getLastRole() const = 0;

    virtual QSqlQuery &getQuery() = 0;

    quint32 getAttemptsCount() const { return mRequestAttemptsCount; }
    void setAttemptsCount(quint32 count) { mRequestAttemptsCount = count; }

    int getRequestBatchSize() const { return mRequestBatchSize; }
    void setRequestBatchSize(quint32 size) { mRequestBatchSize = size; }

    ServerApi *getServerApi() const { return mApi; }
    IcoImageProvider *getIcoImageProvider() const { return mImageProvider; }
    QSettings *getSettings() const { return mSettings; }

    void setRoleName(int role, const QByteArray &name) const { mRoleNames[role] = name; }

    void emitServerDataReceived()
    { emit serverDataReceived(); }

    /// reimplemented qt methods
    QVariant data(const QModelIndex &item, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

private slots:
    void _setFilter(QString filter);

private:
    mutable QHash<int, QByteArray> mRoleNames;

    quint32 mRequestAttemptsCount;
    quint32 mRequestBatchSize;

    ServerApi *mApi;
    IcoImageProvider *mImageProvider;
    QSettings *mSettings;
};

#endif // LISTSQLMODEL_H
