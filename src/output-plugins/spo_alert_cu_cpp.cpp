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

// Barnyard2 headers
#include "unified2.h"
#include "util.h"
//#include "log_text.h" CANNOT COMPILE
//#include "sf_textlog.h" CANNOT COMPILE
//#include "barnyard2.h" CANNOT COMPILE

// KyotoTycoon headers
//#include "cmdcommon.h" CANNOT COMPILE
#include <ktremotedb.h>

#include "spo_alert_cu.h"
#include "spo_alert_cu_cpp.h"
#include "spo_alert_cu_kt.h"
#include "spo_alert_cu_util.h"

#include "spo_alert_cu_interface.h"
#include "spo_alert_cu_client.h"

// **************************************************************************
// file内宣言

// **************************************************************************
// global variables

std::vector<CIDNNode *> g_nodes; // 全てのノードが入ったノードリスト とりあえずのDHTの代わり
std::vector<std::string> g_features; // サイトの特徴リスト
std::vector<std::string> g_domainids; // 参加しているドメインリスト
std::vector<std::string> g_ktargs; // KyotoTycoonの引数

// CIDNの管理クラス
iCIDNManager *g_manager = NULL;

// **************************************************************************

// 終了処理
extern "C" void AlertCuCleanExitFuncCpp(int signal, SpoAlertCuData *ctx) {

    TRACEP("**** AlertCuCleanExitFuncCpp called");

    // 最後に処理を行う
    // このコールバックは通常の終了時には呼び出されないようだ

    // コントローラ削除
    if (g_manager) {
		delete g_manager;
		g_manager = NULL;
    }

	// コンテキスト削除
	delete ctx->conf;

}

// 初期処理
extern "C" void AlertCuInitCpp(SpoAlertCuData *ctx) {

	TRACEP("**** OpAlertCuInitCpp called");

	// アーキテクチャでコントローラを変える
	// 全て集中型とする
    if (0 == ctx->architecture) {
    	// 全ノード共有のマネージャ作成
		g_manager = new CIDNManagerAll(ctx);
    } else if (1 == ctx->architecture) {
    	// 全ドメイン共有のマネージャ作成
		g_manager = new CIDNManager1Stage(ctx);
    } else if (2 == ctx->architecture) {
		// 特定ドメイン共有のマネージャ作成
		g_manager = new CIDNManager2Stage(ctx);
    } else {
    	abort();
    }
    // 初期化
    g_manager->init();

    // ローカルのktserverが起動するまで待つ
    sleep(60);

    // CIDNに参加する。
    g_manager->joinCIDN();

 	// batch modeではない場合、タイマーを設定
 	if (!ctx->isBatchMode) {
 		g_manager->setTimer();
 	}

	return;

}

// アラート処理
extern "C" void AlertCuProcess(PacketCpp *p, Unified2EventCommon *event, char *ip_src_str, int port_src, char *ip_dst_str, int port_dst, SpoAlertCuData *ctx) {

//	TRACEP0("**** processing AlertCuProcess() ****");

	// timestampを読めるように変換する
	char timestamp[TIMEBUF_SIZE];
	memset(timestamp, 0x00, sizeof(timestamp));

	timeval tv;
	if (p->pkth){
		if (ctx->fakeData) {
			// 作ったunified2データを使う場合
			// unified2データを作り出すためにイベントの方の時刻を使うことにした。通常はよくわからないものが入っている。
			timeval ts2;
			ts2.tv_sec = event->event_second;
			ts2.tv_usec = event->event_microsecond;
			tv = ts2;
		} else {
			// 実データを使う場合
			// たぶんpcapヘッダを使う?
			tv = p->pkth->ts;
		}
		formatTimeStampCpp(&tv, timestamp);
		TRACEP5("src [%s:%d] dst [%s:%d] timestamp [%s]", ip_src_str, p->sp, ip_dst_str, p->dp, timestamp);
	} else {
//		TRACEP4("src [%s:%d] dst [%s:%d]", ip_src_str, p->sp, ip_dst_str, p->dp);
	}

    if (event != NULL) {
    } else {
    	TRACEP0( "**** event is NULL ****");
    }

    // local alert store に貯めこむ
    PacketData pdata;
    pdata.p = p;
    pdata.ip_src_str = ip_src_str;
    pdata.port_src = port_src;
    pdata.ip_dst_str =ip_dst_str;
    pdata.port_dst = port_dst;
    pdata.tv = &tv;

    bool result = g_manager->storeAlert(&pdata);

	return;

}

// END OF FILE

