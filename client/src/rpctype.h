#ifndef RPCTYPE_H
#define RPCTYPE_H

#include <QJsonObject>
#include <QJsonArray>

template<typename T>
struct RpcType
{
    RpcType()
        : id(0)
    { }

    quint32 id;

    bool isValid() const
    {
        return id != 0;
    }

    static T fromJsonObject(const QJsonObject &obj)
    {
        T result;
        result.id = obj["id"].toInt();
        return result;
    }

    static QList<T> fromJsonArray(const QJsonArray &arr) {
        QList<T> result;
        for (QJsonValue val : arr) {
            const T t = T::fromJsonObject(val.toObject());
            if (t.isValid()) {
                result.append(t);
            }
        }
        return result;
    }
};

#endif // RPCTYPE_H
