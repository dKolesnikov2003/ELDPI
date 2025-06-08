#ifndef CAPTUREWORKER_H
#define CAPTUREWORKER_H

#include <QThread>
extern "C" {
#include "eldpi_api.h"
}

class CaptureWorker : public QThread
{
    Q_OBJECT
public:
    explicit CaptureWorker(QObject *parent = nullptr);
    ~CaptureWorker();
    CapArgs args;
    void run() override;
public slots:
    void stop();
signals:
    void finished();
private:
    Contexts *ctx;
};

#endif // CAPTUREWORKER_H
