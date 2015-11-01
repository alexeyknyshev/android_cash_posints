#include "icoimageprovider.h"

#include <QtSvg/QSvgRenderer>
#include <QtGui/QPainter>
#include <QDebug>

IcoImageProvider::IcoImageProvider()
    : QQuickImageProvider(QQmlImageProviderBase::Image)
{ }

QImage IcoImageProvider::requestImage(const QString &id, QSize *size, const QSize &requestedSize)
{
    auto it = mRenderers.find(id);
    if (it == mRenderers.end()) {
        if (size) {
            *size = QSize();
        }
        return QImage();
    }

    QSvgRenderer *renderer = it.value();
//    qDebug() << requestedSize;

    QSize imageSize = renderer->defaultSize();
    if (size) {
        if (requestedSize.isValid()) {
            *size = requestedSize;
            imageSize = requestedSize;
        } else {
            *size = imageSize;
        }
    }
    QImage image(imageSize, QImage::Format_ARGB32);
    image.fill(Qt::transparent);

    QPainter painter(&image);
    renderer->render(&painter, QRectF(QPointF(), requestedSize));

    return image;
}

bool IcoImageProvider::loadSvgImage(const QString &name, const QByteArray &data)
{
    QSvgRenderer *renderer = new QSvgRenderer;
    if (!renderer->load(data)) {
        delete renderer;
        return false;
    }

    unloadSvgImage(name);

    mRenderers[name] = renderer;
    return true;
}

bool IcoImageProvider::unloadSvgImage(const QString &name)
{
    auto it = mRenderers.find(name);
    if (it != mRenderers.end()) {
        QSvgRenderer *oldRenderer = it.value();
        mRenderers.erase(it);
        delete oldRenderer;
        return true;
    }
    return false;
}
