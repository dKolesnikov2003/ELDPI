#include "mainwindow.h"
#include "captureworker.h"

#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QSplitter>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFile>
#include <QByteArray>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QDateTime>
#include <QMessageBox>
#include <QMovie>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), worker(nullptr)
{
    dataDir = QString::fromUtf8(get_data_dir());
    metadataDb = QSqlDatabase::addDatabase("QSQLITE", "metadata");
    metadataDb.setDatabaseName(dataDir + "/metadata.db");
    metadataDb.open();
    offsetsDb = QSqlDatabase::addDatabase("QSQLITE", "offsets");
    offsetsDb.setDatabaseName(dataDir + "/offsets.db");
    offsetsDb.open();
    setupUi();
    populateAnalysisList();
}

MainWindow::~MainWindow()
{
    if(worker){
        worker->stop();
        worker->wait();
        delete worker;
    }
    metadataDb.close();
    offsetsDb.close();
}

void MainWindow::setupUi()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    // Top filter layout
    ipEdit = new QLineEdit(this);
    ipEdit->setPlaceholderText(tr("IP"));
    portEdit = new QLineEdit(this);
    portEdit->setPlaceholderText(tr("Port"));
    protoEdit = new QLineEdit(this);
    protoEdit->setPlaceholderText(tr("Protocol"));
    analysisCombo = new QComboBox(this);
    sessionCheck = new QCheckBox(tr("Group by session"), this);

    QPushButton *applyButton = new QPushButton(tr("Apply"), this);
    connect(applyButton, &QPushButton::clicked, this, &MainWindow::applyFilters);

    QHBoxLayout *topLayout = new QHBoxLayout;
    topLayout->addWidget(ipEdit);
    topLayout->addWidget(portEdit);
    topLayout->addWidget(protoEdit);
    topLayout->addWidget(analysisCombo);
    topLayout->addWidget(sessionCheck);
    topLayout->addWidget(applyButton);

    // Tree and packet view
    tree = new QTreeWidget(this);
    tree->setColumnCount(8);
    QStringList headers;
    headers << "timestamp" << "session" << "ip_ver" << "ip_src" << "ip_dst" << "src_port" << "dst_port" << "protocol";
    tree->setHeaderLabels(headers);
    tree->setAlternatingRowColors(true);
    tree->setSortingEnabled(true);
    tree->setStyleSheet("QTreeView::item { border-bottom: 1px solid #dcdcdc; }");
    connect(tree, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onPacketDoubleClicked);

    packetView = new QPlainTextEdit(this);
    packetView->setReadOnly(true);

    QSplitter *split = new QSplitter(this);
    split->addWidget(tree);
    split->addWidget(packetView);
    split->setStretchFactor(0,3);
    split->setStretchFactor(1,2);

    // Bottom controls
    sourceTypeCombo = new QComboBox(this);
    sourceTypeCombo->addItem(tr("File"), CAP_SRC_FILE);
    sourceTypeCombo->addItem(tr("Interface"), CAP_SRC_IFACE);
    sourceEdit = new QLineEdit(this);
    bpfEdit = new QLineEdit(this);
    bpfEdit->setPlaceholderText(tr("BPF filter"));
    startButton = new QPushButton(tr("Start"), this);
    stopButton = new QPushButton(tr("Stop"), this);
    stopButton->setEnabled(false);

    connect(startButton, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(stopButton, &QPushButton::clicked, this, &MainWindow::stopCapture);

    QHBoxLayout *bottomLayout = new QHBoxLayout;
    bottomLayout->addWidget(sourceTypeCombo);
    bottomLayout->addWidget(sourceEdit);
    bottomLayout->addWidget(bpfEdit);
    bottomLayout->addWidget(startButton);
    bottomLayout->addWidget(stopButton);

    loadingLabel = new QLabel(this);
    loadingLabel->setAlignment(Qt::AlignCenter);
    loadingLabel->setVisible(false);

    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->addLayout(topLayout);
    mainLayout->addWidget(split);
    mainLayout->addWidget(loadingLabel);
    mainLayout->addLayout(bottomLayout);
}

void MainWindow::populateAnalysisList()
{
    analysisCombo->clear();
    QSqlQuery q(metadataDb);
    q.exec("SELECT name FROM sqlite_master WHERE type='table'");
    while(q.next()) {
        QString name = q.value(0).toString();
        analysisCombo->addItem(name);
    }
    if(analysisCombo->count())
        loadTable();
}

void MainWindow::loadTable()
{
    fillTree();
}

void MainWindow::applyFilters()
{
    fillTree();
}

void MainWindow::fillTree()
{
    tree->clear();
    QString table = analysisCombo->currentText();
    if(table.isEmpty()) return;
    QString queryStr = QString("SELECT timestamp_us, session_id, ip_version, ip_src, ip_dst, src_port, dst_port, protocol_name FROM \"") + table + "\"";
    QSqlQuery q(metadataDb);
    if(!q.exec(queryStr)) return;

    struct Packet { qulonglong ts; qulonglong session; int ipver; QString src; QString dst; int sport; int dport; QString proto; };
    QMap<qulonglong, QList<Packet>> sessions;
    QMap<qulonglong, QMap<QString,int>> protoCount;

    while(q.next()) {
        Packet p;
        p.ts = q.value(0).toULongLong();
        p.session = q.value(1).toULongLong();
        p.ipver = q.value(2).toInt();
        p.src = q.value(3).toString();
        p.dst = q.value(4).toString();
        p.sport = q.value(5).toInt();
        p.dport = q.value(6).toInt();
        p.proto = q.value(7).toString();
        if(!ipEdit->text().isEmpty() && !p.src.contains(ipEdit->text()) && !p.dst.contains(ipEdit->text()))
            continue;
        if(!portEdit->text().isEmpty() && QString::number(p.sport) != portEdit->text() && QString::number(p.dport) != portEdit->text())
            continue;
        if(!protoEdit->text().isEmpty() && !p.proto.contains(protoEdit->text(), Qt::CaseInsensitive))
            continue;
        sessions[p.session].append(p);
        protoCount[p.session][p.proto]++;
    }

    bool group = sessionCheck->isChecked();
    if(group) {
        for(auto it = sessions.begin(); it != sessions.end(); ++it) {
            qulonglong sessionId = it.key();
            QList<Packet> packets = it.value();
            QString proto;
            int maxCnt = 0;
            for(auto pit = protoCount[sessionId].begin(); pit != protoCount[sessionId].end(); ++pit) {
                if(pit.value() > maxCnt) { maxCnt = pit.value(); proto = pit.key(); }
            }
            QTreeWidgetItem *sessionItem = new QTreeWidgetItem(tree);
            sessionItem->setText(0, QString("session %1").arg(sessionId));
            sessionItem->setText(7, proto);
            for(const Packet &p : packets) {
                QTreeWidgetItem *item = new QTreeWidgetItem(sessionItem);
                item->setText(0, QString::number(p.ts));
                item->setText(1, QString::number(p.session));
                item->setText(2, QString::number(p.ipver));
                item->setText(3, p.src);
                item->setText(4, p.dst);
                item->setText(5, QString::number(p.sport));
                item->setText(6, QString::number(p.dport));
                item->setText(7, p.proto);
                item->setData(0, Qt::UserRole, QVariant::fromValue(p.ts));
            }
        }
    } else {
        for(auto it = sessions.begin(); it != sessions.end(); ++it) {
            for(const Packet &p : it.value()) {
                QTreeWidgetItem *item = new QTreeWidgetItem(tree);
                item->setText(0, QString::number(p.ts));
                item->setText(1, QString::number(p.session));
                item->setText(2, QString::number(p.ipver));
                item->setText(3, p.src);
                item->setText(4, p.dst);
                item->setText(5, QString::number(p.sport));
                item->setText(6, QString::number(p.dport));
                item->setText(7, p.proto);
                item->setData(0, Qt::UserRole, QVariant::fromValue(p.ts));
            }
        }
    }
    tree->expandAll();
}

QByteArray MainWindow::readPacket(qulonglong timestamp)
{
    QString table = analysisCombo->currentText();
    if(table.isEmpty()) return QByteArray();
    QString qstr = QString("SELECT file_offset, packet_len FROM \"") + table + "\" WHERE timestamp_us=" + QString::number(timestamp);
    QSqlQuery q(offsetsDb);
    if(!q.exec(qstr)) return QByteArray();
    if(!q.next()) return QByteArray();
    quint64 offset = q.value(0).toULongLong();
    int len = q.value(1).toInt();
    QString pcapPath = dataDir + "/" + table + ".pcap";
    QFile f(pcapPath);
    if(!f.open(QIODevice::ReadOnly)) return QByteArray();
    if(!f.seek(offset)) return QByteArray();
    return f.read(len);
}

void MainWindow::onPacketDoubleClicked(QTreeWidgetItem *item, int)
{
    if(!item || item->childCount()>0) return; // skip session items
    qulonglong ts = item->data(0, Qt::UserRole).toULongLong();
    QByteArray data = readPacket(ts);
    if(data.isEmpty()) return;
    QString dump;
    const int bytesPerLine = 16;
    for(int i = 0; i < data.size(); i += bytesPerLine) {
        dump += QString("%1  ").arg(i, 8, 16, QChar('0'));
        QString ascii;
        for(int j = 0; j < bytesPerLine; ++j) {
            int idx = i + j;
            if(idx < data.size()) {
                unsigned char b = static_cast<unsigned char>(data[idx]);
                dump += QString("%1 ").arg(b, 2, 16, QChar('0'));
                if(j == 7)
                    dump += " ";
                ascii += (b >= 32 && b <= 126) ? QChar(b) : QChar('.');
            } else {
                dump += "   ";
                if(j == 7)
                    dump += " ";
                ascii += ' ';
            }
        }
        dump += " " + ascii;
        if(i + bytesPerLine < data.size())
            dump += '\n';
    }
    packetView->setPlainText(dump.toUpper());
}

void MainWindow::startCapture()
{
    if(worker) {
        QMessageBox::warning(this, tr("Capture"), tr("Capture already running"));
        return;
    }
    worker = new CaptureWorker(this);
    memset(&worker->args,0,sizeof(CapArgs));
    worker->args.source_type = (CapSrc)sourceTypeCombo->currentData().toInt();
    QByteArray src = sourceEdit->text().toUtf8();
    worker->args.source_name = strdup(src.constData());
    QByteArray bpf = bpfEdit->text().toUtf8();
    if(!bpf.isEmpty())
        worker->args.bpf = strdup(bpf.constData());
    char* dt = (char*)calloc(20,1);
    QDateTime now = QDateTime::currentDateTime();
    strcpy(dt, now.toString("yyyy-MM-dd HH:mm:ss").toUtf8().constData());
    worker->args.date_time = dt;

    connect(worker, &CaptureWorker::finished, this, &MainWindow::captureFinished);

    tree->setVisible(false);
    packetView->clear();
    loadingLabel->setVisible(true);
    QMovie *mv = new QMovie(":/qt-project.org/styles/commonstyle/images/working-32.gif");
    loadingLabel->setMovie(mv);
    mv->start();

    startButton->setEnabled(false);
    stopButton->setEnabled(worker->args.source_type==CAP_SRC_IFACE);
    worker->start();
}

void MainWindow::stopCapture()
{
    if(worker)
        worker->stop();
}

void MainWindow::captureFinished()
{
    loadingLabel->movie()->stop();
    loadingLabel->setVisible(false);
    tree->setVisible(true);
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    populateAnalysisList();
    worker->wait();
    free(worker->args.source_name);
    free(worker->args.bpf);
    free(worker->args.date_time);
    worker->deleteLater();
    worker = nullptr;
}
