#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSqlDatabase>

extern "C" {
#include "eldpi_api.h"
}

class QTreeWidget;
class QTreeWidgetItem;
class QLineEdit;
class QComboBox;
class QCheckBox;
class QPlainTextEdit;
class QLabel;
class QPushButton;
class CaptureWorker;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void loadTable();
    void applyFilters();
    void onPacketDoubleClicked(QTreeWidgetItem *, int);
    void startCapture();
    void stopCapture();
    void captureFinished();

private:
    void setupUi();
    void populateAnalysisList();
    void fillTree();
    QByteArray readPacket(qulonglong timestamp);

    QSqlDatabase metadataDb;
    QSqlDatabase offsetsDb;

    QTreeWidget *tree;
    QPlainTextEdit *packetView;
    QLineEdit *ipEdit;
    QLineEdit *portEdit;
    QLineEdit *protoEdit;
    QComboBox *analysisCombo;
    QCheckBox *sessionCheck;

    QLineEdit *sourceEdit;
    QLineEdit *bpfEdit;
    QComboBox *sourceTypeCombo;
    QPushButton *startButton;
    QPushButton *stopButton;
    QLabel *loadingLabel;

    CaptureWorker *worker;
    QString dataDir;
};

#endif // MAINWINDOW_H
