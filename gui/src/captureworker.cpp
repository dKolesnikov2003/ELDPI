#include "captureworker.h"

CaptureWorker::CaptureWorker(QObject *parent)
    : QThread(parent), ctx(nullptr)
{
}

CaptureWorker::~CaptureWorker()
{
}

void CaptureWorker::run()
{
    ctx = start_analysis(&args);
    if(!ctx) {
        emit finished();
        return;
    }
    if(args.source_type == CAP_SRC_FILE) {
        wait_analysis(ctx);
        destroy_analysis_context(ctx);
        ctx = nullptr;
        emit finished();
    }
    
}

void CaptureWorker::stop()
{
    if(ctx) {
        stop_analysis(ctx);
        destroy_analysis_context(ctx);
        ctx = nullptr;
        emit finished();
    }
}
