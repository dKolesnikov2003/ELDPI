#include "mainwindow.h"
#include "captureworker.h"

#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QSplitter>
#include <QTableWidget>
#include <QHeaderView>
#include <QFontDatabase>
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
#include <QFontDatabase> 

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
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSize(mono.pointSize() + 2);
    packetView->setFont(mono); 
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
    portEdit->setPlaceholderText(tr("Порт"));
    protoEdit = new QLineEdit(this);
    protoEdit->setPlaceholderText(tr("Протокол"));
    analysisCombo = new QComboBox(this);
    connect(analysisCombo, &QComboBox::currentTextChanged,
            this, &MainWindow::loadTable);
    sessionCheck = new QCheckBox(tr("Группировать по сессии"), this);
    connect(sessionCheck, &QCheckBox::toggled,
            this, &MainWindow::fillTree);

    QPushButton *applyButton = new QPushButton(tr("Применить"), this);
    connect(applyButton, &QPushButton::clicked, this, &MainWindow::applyFilters);

    QHBoxLayout *topLayout = new QHBoxLayout;
    // move data source selection and session checkbox to the beginning
    topLayout->addWidget(analysisCombo);
    topLayout->addWidget(sessionCheck);
    topLayout->addWidget(ipEdit);
    topLayout->addWidget(portEdit);
    topLayout->addWidget(protoEdit);
    topLayout->addWidget(applyButton);

    // Tree and packet view
    tree = new QTreeWidget(this);
    tree->setColumnCount(8);
    QStringList headers;
    headers << "Время" << "Сессия" << "Версия IP" << "IP источника" << "IP назначения" << "Порт источника" << "Порт назначения" << "Протокол/Приложение";
    tree->setHeaderLabels(headers);
    // Make metadata columns wider by default for better readability
    QHeaderView *treeHeader = tree->header();
    treeHeader->resizeSection(0, 300); // Time
    treeHeader->resizeSection(1, 100);  // Session
    treeHeader->resizeSection(2, 100);  // IP version
    treeHeader->resizeSection(3, 250); // Source IP
    treeHeader->resizeSection(4, 250); // Destination IP
    treeHeader->resizeSection(5, 160); // Source port
    treeHeader->resizeSection(6, 160); // Destination port
    treeHeader->resizeSection(7, 160); // Protocol
    tree->setAlternatingRowColors(true);
    tree->setSortingEnabled(true);
    // tree->setStyleSheet();
    connect(tree, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onPacketDoubleClicked);

    packetView = new QTableWidget(this);
    packetView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetView->setSelectionMode(QAbstractItemView::SingleSelection);
    packetView->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetView->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    packetView->verticalHeader()->setDefaultAlignment(Qt::AlignRight|Qt::AlignVCenter);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSize(mono.pointSize() + 2);
    packetView->setFont(mono);

    QSplitter *split = new QSplitter(this);
    split->addWidget(tree);
    split->addWidget(packetView);
    split->setStretchFactor(0,2);
    split->setStretchFactor(1,1);

    // Bottom controls
    sourceTypeCombo = new QComboBox(this);
    sourceTypeCombo->addItem(tr("Файл"), CAP_SRC_FILE);
    sourceTypeCombo->addItem(tr("Интерфейс"), CAP_SRC_IFACE);
    sourceEdit = new QLineEdit(this);
    bpfEdit = new QLineEdit(this);
    bpfEdit->setPlaceholderText(tr("Фильтр BPF"));
    startButton = new QPushButton(tr("Начать"), this);
    stopButton = new QPushButton(tr("Остановить"), this);
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
        if(name == QLatin1String("sqlite_sequence"))
            continue; 
        analysisCombo->addItem(name);
    }
    if(analysisCombo->count()) {
        analysisCombo->setCurrentIndex(analysisCombo->count()-1);
        loadTable();
    }
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
        int colorIndex = 0;
        for(auto it = sessions.begin(); it != sessions.end(); ++it) {
            qulonglong sessionId = it.key();
            QList<Packet> packets = it.value();
            QString proto;
            int maxCnt = 0;
            for(auto pit = protoCount[sessionId].begin(); pit != protoCount[sessionId].end(); ++pit) {
                if(pit.value() > maxCnt) { maxCnt = pit.value(); proto = pit.key(); }
            }
            QColor base = QColor::fromHsv((colorIndex * 45) % 360, 80, 230);
            QColor child = base.lighter(142);
            QTreeWidgetItem *sessionItem = new QTreeWidgetItem(tree);
            sessionItem->setText(0, QString("сессия %1").arg(sessionId));
            sessionItem->setText(7, proto);
            for(int c=0; c<tree->columnCount(); ++c){
                sessionItem->setBackground(c, QBrush(base));
                QFont f = sessionItem->font(c);
                f.setBold(true);
                sessionItem->setFont(c, f);
            }
            for(const Packet &p : packets) {
                QTreeWidgetItem *item = new QTreeWidgetItem(sessionItem);
                item->setText(0, formatTimestamp(p.ts));
                item->setText(1, QString::number(p.session));
                item->setText(2, QString::number(p.ipver));
                item->setText(3, p.src);
                item->setText(4, p.dst);
                item->setText(5, QString::number(p.sport));
                item->setText(6, QString::number(p.dport));
                item->setText(7, p.proto);
                item->setData(0, Qt::UserRole, QVariant::fromValue(p.ts));
                for(int c=0;c<tree->columnCount();++c)
                    item->setBackground(c, QBrush(child));
            }
            colorIndex++;
        }
    } else {
        for(auto it = sessions.begin(); it != sessions.end(); ++it) {
            for(const Packet &p : it.value()) {
                QTreeWidgetItem *item = new QTreeWidgetItem(tree);
                item->setText(0, formatTimestamp(p.ts));
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
    const int bytesPerLine = 16;
    int rows = (data.size() + bytesPerLine - 1) / bytesPerLine;
    packetView->clear();
    packetView->setColumnCount(bytesPerLine + 1);
    packetView->setRowCount(rows);

    for(int i = 0; i < bytesPerLine; ++i){
        QTableWidgetItem *hh = new QTableWidgetItem(QString("%1").arg(i, 2, 16, QChar('0')).toUpper());
        hh->setForeground(QBrush(Qt::darkGray));
        packetView->setHorizontalHeaderItem(i, hh);
    }
    QTableWidgetItem *asciiHeader = new QTableWidgetItem("ASCII");
    asciiHeader->setForeground(QBrush(Qt::darkGray));
    packetView->setHorizontalHeaderItem(bytesPerLine, asciiHeader);

    for(int row = 0; row < rows; ++row) {
        int offset = row * bytesPerLine;
        QTableWidgetItem *vh = new QTableWidgetItem(QString("%1").arg(offset, 8, 16, QChar('0')).toUpper());
        vh->setForeground(QBrush(Qt::darkGray));
        packetView->setVerticalHeaderItem(row, vh);

        QString ascii;
        for(int col = 0; col < bytesPerLine; ++col) {
            int idx = offset + col;
            QTableWidgetItem *cell = new QTableWidgetItem;
            cell->setTextAlignment(Qt::AlignCenter);
            if(idx < data.size()) {
                unsigned char b = static_cast<unsigned char>(data[idx]);
                cell->setText(QString("%1").arg(b, 2, 16, QChar('0')).toUpper());
                ascii += (b >= 32 && b <= 126) ? QChar(b) : QChar('.');
            } else {
                cell->setText("  ");
                ascii += ' ';
            }
            packetView->setItem(row, col, cell);
        }
        QTableWidgetItem *asciiItem = new QTableWidgetItem(ascii);
        asciiItem->setForeground(QBrush(Qt::blue));
        packetView->setItem(row, bytesPerLine, asciiItem);
    }

    for(int c = 0; c < bytesPerLine; ++c)
        packetView->setColumnWidth(c, 30);
    auto *h = packetView->horizontalHeader();
    h->setSectionResizeMode(bytesPerLine, QHeaderView::Stretch);
    h->setStretchLastSection(true);
    
}

void MainWindow::startCapture()
{
    if(worker) {
        QMessageBox::warning(this, tr("Захват"), tr("Захват уже запущен"));
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
    packetView->setVisible(false);
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
    packetView->setVisible(true);
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    metadataDb.close();
    offsetsDb.close();
    metadataDb.open();
    offsetsDb.open();
    populateAnalysisList();
    worker->wait();
    free(worker->args.source_name);
    free(worker->args.bpf);
    free(worker->args.date_time);
    worker->deleteLater();
    worker = nullptr;
}

QString MainWindow::formatTimestamp(qulonglong ts) const
{
    qint64 ms = static_cast<qint64>(ts / 1000ULL);
    QDateTime dt = QDateTime::fromMSecsSinceEpoch(ms);
    return dt.toString("yyyy-MM-dd HH:mm:ss.zzz");
}
