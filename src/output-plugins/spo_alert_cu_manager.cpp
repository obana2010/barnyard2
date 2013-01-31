#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// **************************************************************************
// include headers

// C headers
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>

// C++ headers
#include <sstream>

// Barnyard2 headers
#include "unified2.h"
#include "util.h"

// KyotoTycoon headers
//#include "cmdcommon.h"
#include <ktremotedb.h>
#include "spo_alert_cu.h"
#include "spo_alert_cu_cpp.h"
#include "spo_alert_cu_kt.h"
#include "spo_alert_cu_util.h"
#include "spo_alert_cu_interface.h"
#include "spo_alert_cu_client.h"

// **************************************************************************

// global alert store
extern kyotocabinet::GrassDB *g_gGrassDB;
// ブラックリスト 送信元IP => タイムスロット
extern kyotocabinet::GrassDB *g_blacklist;
// コンテキスト やっぱりグローバルにあるほうが楽
SpoAlertCuData *g_ctx;

// クラス変数
CIDNManagerImpl *CIDNManagerImpl::m_imanager;

// ****************************************************************************
// static functions

// KyotoTycoonを起動する
static void *kickktmain(void *arg) {

	TRACEP("$$$$ kickktmain")

	SpoAlertCuData *ctx = (SpoAlertCuData *) arg;
	std::map<std::string, std::string> *conf = (std::map<std::string, std::string> *)ctx->conf;

	// YAMLから設定
	char **argv = new char *[g_ktargs.size()];
	for(size_t i = 0; i < g_ktargs.size(); i++) {
	  std::string &arg_str = g_ktargs[i];
	  size_t size = arg_str.size();
	  char *arg = new char[size + 1];
	  memset(arg, 0x00, size + 1);
	  strncpy(arg, arg_str.c_str(), size);
	  argv[i] = arg;
	}

	int rv = ktmain(g_ktargs.size(), argv);
	delete[] argv;
	return NULL;

}

// IDから接続するサーバのIPとポートを取得する
bool CIDNManagerImpl::getRemoteServer(const char *id, char *ip, size_t ipsize, int *port) {

  	assert(id);
  	assert(ip);
  	assert(port);

  	// TODO 必ずnodes[0]に接続
  	CIDNNode *node = g_nodes[0];
  	strncpy(ip, node->ip.c_str(), ipsize);
  	*port = atoi(node->port.c_str());
  	TRACEP2("**** getRemoteServer [%s:%d]", ip, *port);

  	return true;

}

// idからサーバに接続する
bool CIDNManagerImpl::connectRemoteServer(kyototycoon::RemoteDB &client, std::string &id_str) {

	TRACEP1("**** connectRemoteServer [%s]", id_str);

	// IDからサーバを取得する
	char ip[100];
	int port;
	if (!getRemoteServer(id_str.c_str(), ip, sizeof(ip), &port)) {
		abort();
		return false;
	}

	// サーバに接続する
	bool result = client.open(ip, port, 5);

	if (!result){
		TRACEP3("**** failed to open client [%s] [%s]] [%s] ****", id_str.c_str(), client.error().name(), client.error().message());
		return false;
	}
	return true;

}

// ****************************************************************************

// CIDN参加
bool CIDNManagerImpl::joinCIDN() {

    // ドメイン参加要求をだす
    for (int i = 0; i < g_domainids.size(); i++) {
    	std::string &domainid = g_domainids[i];

		// 登録すべきサーバを取得する
    	DomainListManagerDB client;
		bool result = connectRemoteServer(client, domainid);
		if (!result){
			// TODO 接続失敗
			abort();
		} else {
			// domain list holderにドメイン参加要求をだす
			result = client.joinDomain(domainid, this->m_ctx->cktip, this->m_ctx->cktport);
			if (!result) {
				TRACEP2("**** joinDomain failed: [%1%] [%2%]", client.error().name(), client.error().message());
				return false;
			}
			client.close();
		}

    }
    return true;
}

// 初期化
bool CIDNManagerImpl::init() {

	TRACEP("**** CIDNManagerImpl::init()");

	// local alert store 用のKCを用意する
	this->m_ildb = new AlertStoreDB(this->m_ctx, this);
	// 初期化
	if (!this->m_ildb->init()) {
		TRACEP("**** init failed");
		abort();
	}
	TRACEP("**** opend local alert store");

	// global alert store 用のKCを用意する
	g_gGrassDB = new kyotocabinet::GrassDB();
	if (!g_gGrassDB->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_gGrassDB->error().name());
		abort();
	}
	TRACEP("**** opend global alert store");

	// ブラックリスト用のKCを用意する
	g_blacklist = new kyotocabinet::GrassDB();
	if (!g_blacklist->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_blacklist->error().name());
		abort();
	}
	TRACEP("**** opend blacklist");

	// 受信用のKyotoTycoon実行
	pthread_t pt;
	pthread_create(&pt, NULL, kickktmain, this->m_ctx);

	return true;

}

// 閾値超過監視用のタイマーをセットする
// timer_createに変更するかも
bool CIDNManagerImpl::setTimer() {

	// SIGALRMのコールバックを設定
	signal(SIGALRM, CIDNManagerImpl::timerCallback);

	struct itimerval timeset;

	// 反復インターバル
	timeset.it_interval.tv_sec = (this->m_ctx->localAlertTimeSlotSize * this->m_ctx->timeSlotSize);
	timeset.it_interval.tv_usec = 0;
	// 初期インターバル
	timeset.it_value.tv_sec = (this->m_ctx->localAlertTimeSlotSize * this->m_ctx->timeSlotSize);
	timeset.it_value.tv_usec = 0;

	TRACEP1("setTimer [%1%]sec", (this->m_ctx->localAlertTimeSlotSize * this->m_ctx->timeSlotSize));

	setitimer(ITIMER_REAL, &timeset, NULL);

	return true;

}

// タイマーのコールバック用クラスメソッド
void CIDNManagerImpl::timerCallback(int signum) {

	CIDNManagerImpl::m_imanager->timerCallback();

}

// 閾値超過チェックを呼び出す
bool CIDNManagerImpl::timerCallback() {

	// 現在のタイムスロットを設定
    timeval tv;
    gettimeofday(&tv, NULL);
	unsigned long timeslot = tv.tv_sec / (this->m_ctx->localAlertTimeSlotSize * this->m_ctx->timeSlotSize);
	this->m_ctx->current_timeslot = timeslot;

	// 閾値超過判定ルーチンを呼び出す
	this->m_ildb->checkThreshold();

	return true;
}

// 終了処理
bool CIDNManagerImpl::exit() {

	TRACEP("**** CIDNManagerImpl::exit()");

	// 終了処理を行う
    if (this->m_ildb) {
		this->m_ildb->exit();
		delete this->m_ildb;
		this->m_ildb = NULL;
    }
    if (g_gGrassDB) {
		delete g_gGrassDB;
		g_gGrassDB = NULL;
    }

	return true;
}

// アラート処理
bool CIDNManagerImpl::storeAlert(PacketData *pdata) {

    // local alert store に貯めこむ
    bool result = this->m_ildb->storeAlert(pdata);

	return result;

}

// コンストラクタ
CIDNManagerImpl::CIDNManagerImpl(SpoAlertCuData *ctx) : iCIDNManager(ctx) {
	CIDNManagerImpl::m_imanager = this;
	return;
}

// デストラクタ
CIDNManagerImpl::~CIDNManagerImpl() {
	// 終了処理を呼び出す
	this->exit();
	return;
}

// ****************************************************************************
//

// コンストラクタ
CIDNManagerAll::CIDNManagerAll(SpoAlertCuData *ctx) : CIDNManagerImpl(ctx) {
	return;
}

// デストラクタ
CIDNManagerAll::~CIDNManagerAll() {
	return;
}

// 初期化
bool CIDNManagerAll::init() {

	TRACEP("**** CIDNManagerImpl::init()");

	// local alert store 用のKCを用意する
	this->m_ildb = new AlertStoreDBAll(this->m_ctx, this);
	// 初期化
	if (!this->m_ildb->init()) {
		TRACEP("**** init failed");
		abort();
	}

	// global alert store 用のKCを用意する
	g_gGrassDB = new kyotocabinet::GrassDB();
	if (!g_gGrassDB->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_gGrassDB->error().name());
		abort();
	}
	TRACEP("**** opend global alert store");

	// ブラックリスト用のKCを用意する
	g_blacklist = new kyotocabinet::GrassDB();
	if (!g_blacklist->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_blacklist->error().name());
		abort();
	}
	TRACEP("**** opend blacklist");

	// 受信用のKyotoTycoon実行
	pthread_t pt;
	pthread_create(&pt, NULL, kickktmain, this->m_ctx);
	return true;

}

// ****************************************************************************
//

// コンストラクタ
CIDNManager1Stage::CIDNManager1Stage(SpoAlertCuData *ctx) : CIDNManagerImpl(ctx) {
	return;
}

// デストラクタ
CIDNManager1Stage::~CIDNManager1Stage() {
	return;
}

// 初期化
bool CIDNManager1Stage::init() {

	TRACEP("**** CIDNManager1Stage::init()");

	// local alert store 用のKCを用意する
	this->m_ildb = new AlertStoreDB1Stage(this->m_ctx, this);
	// 初期化
	if (!this->m_ildb->init()) {
		TRACEP("**** init failed");
		abort();
	}

	// global alert store 用のKCを用意する
	g_gGrassDB = new kyotocabinet::GrassDB();
	if (!g_gGrassDB->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_gGrassDB->error().name());
		abort();
	}
	TRACEP("**** opend global alert store");

	// ブラックリスト用のKCを用意する
	g_blacklist = new kyotocabinet::GrassDB();
	if (!g_blacklist->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_blacklist->error().name());
		abort();
	}
	TRACEP("**** opend blacklist");

	// 受信用のKyotoTycoon実行
	pthread_t pt;
	pthread_create(&pt, NULL, kickktmain, this->m_ctx);

	return true;

}
// ****************************************************************************
//

// コンストラクタ
CIDNManager2Stage::CIDNManager2Stage(SpoAlertCuData *ctx) : CIDNManagerImpl(ctx) {
	return;
}

// デストラクタ
CIDNManager2Stage::~CIDNManager2Stage() {
	return;
}

// 初期化
bool CIDNManager2Stage::init() {

	TRACEP("**** CIDNManager2Stage::init()");

	// local alert store 用のKCを用意する
	this->m_ildb = new AlertStoreDB2Stage(this->m_ctx, this);
	// 初期化
	if (!this->m_ildb->init()) {
		abort();
	}

	// global alert store 用のKCを用意する
	g_gGrassDB = new kyotocabinet::GrassDB();
	if (!g_gGrassDB->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_gGrassDB->error().name());
		abort();
	}
	TRACEP("**** opend global alert store");

	// ブラックリスト用のKCを用意する
	g_blacklist = new kyotocabinet::GrassDB();
	if (!g_blacklist->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		TRACEP1("**** open failed: %1%", g_blacklist->error().name());
		abort();
	}
	TRACEP("**** opend blacklist");

	// 受信用のKyotoTycoon実行
	pthread_t pt;
	pthread_create(&pt, NULL, kickktmain, this->m_ctx);
	return true;

}

// ****************************************************************************
// インターフェイス

// インターフェイスコストラクタ
iAlertStoreDB::iAlertStoreDB(SpoAlertCuData *ctx) {
	this->m_ctx = ctx;
}

// インターフェイスデストラクタ
iAlertStoreDB::~iAlertStoreDB() {
	return;
}

// END OF FILE

