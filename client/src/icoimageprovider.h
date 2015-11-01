#ifndef ICOIMAGEPROVIDER_H
#define ICOIMAGEPROVIDER_H

#include <QtQuick/QQuickImageProvider>

class QSvgRenderer;

class IcoImageProvider : public QQuickImageProvider
{
public:
    IcoImageProvider();

    virtual QImage requestImage(const QString &id,
                                QSize *size,
                                const QSize &requestedSize) override;

    bool loadSvgImage(const QString &name, const QByteArray &data);
    bool unloadSvgImage(const QString &name);

private:
    QMap<QString, QSvgRenderer *> mRenderers;
};

#endif // ICOIMAGEPROVIDER_H
