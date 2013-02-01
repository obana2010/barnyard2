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
kyotocabinet::GrassDB *g_gGrassDB;
// ブラックリスト 送信元IP => タイムスロット
kyotocabinet::GrassDB *g_blacklist;
// ドメインノードリスト ドメインID => ドメインノードリスト
std::map<std::string, std::vector <CIDNNode *> *> g_domainNodeLists;

// 取得済みドメインノードリスト一覧
std::set<std::string> g_domainlists_set;
// ****************************************************************************
// typedef
typedef std::map<std::string, std::string> nodelist_type;
typedef std::map<std::string, std::vector <CIDNNode *> *> nodelistmap_type;
typedef std::map<std::string, unsigned long> blacklist_type;

// ****************************************************************************
// local alert store client
bool AlertStoreDB::storeGlobalAlertData(const std::string &sourceip, const unsigned long timeslot, unsigned long count) {

	TRACEP("**** storeGlobalAlertData called");
	GlobalAlertStoreDB globalAlertStore;

	// ハッシュを求める
	std::string id_str;
	getIDfromStr(sourceip.c_str(), id_str);
	// 接続する
	bool result = this->m_imanager->connectRemoteServer(globalAlertStore, id_str);
	if (!result) {
		return false;
	}

	// ノードIDをIP:PORTとして作成する
	char nodeid[NODEID_MAX];
	formatNodeID(nodeid, NODEID_MAX, this->m_ctx->cktip, this->m_ctx->cktport);

	// global alert storeにアラートを格納する
	result = globalAlertStore.storeGlobalAlert(sourceip, g_domainids, timeslot, count, nodeid);
	if (!result) {
		TRACEP2("**** storeGlobalAlertData failed: [%1%] [%2%]", globalAlertStore.error().name(), globalAlertStore.error().message());
		return false;
	}

	globalAlertStore.close();
	return true;

}

// 初期化
bool AlertStoreDB::init() {

	// GrassDBはソートされたDB
	if (!this->open("*", kyotocabinet::GrassDB::OWRITER | kyotocabinet::GrassDB::OCREATE)) {
		std::cerr << "**** open failed: " << this->error().name() << std::endl;
		return false;
	}
	TRACEP("**** opend local alert store");
	return true;

}

// ブラックリストを共有
// 共有先ノードを指定して1件の共有を行う
bool AlertStoreDB::shareBlacklistNode(CIDNNode &node, std::string &sourceip, std::string &domainid, unsigned long timeslot) {

writelog("shareBlacklistRecord"); // log出力
	TRACEP3("**** share blacklist [%1%][%2%:%3%]", sourceip.c_str(), node.ip.c_str(), node.port.c_str());

	// ノードに接続
	NodeBlacklistDB nodedb;
	bool result = nodedb.open(node.ip.c_str(), atoi(node.port.c_str()));
	if (!result){
		// 失敗しても共有を続ける
		TRACEP2("**** failed to open [%1%:%2%]", node.ip.c_str(), node.port.c_str());
	} else {
		// ブラックリストを共有
		result = nodedb.shareBlacklist(sourceip, domainid, timeslot);
	}
	return result;

}

// ブラックリストを共有
// 共有先ノードのリストを指定してリストのノードに対して共有を行う 重複チェックあり
bool AlertStoreDB::shareBlackListNodes(
		GlobalStoreRecord &globalStoreRecord,
		std::map<std::string, std::string> nodelist,
		std::map<std::string, unsigned long> &sharedBlacklist) {

	// ドメインノードリストでループ
	for (nodelist_type::const_iterator i = nodelist.begin(); i != nodelist.end(); ++i) {
		//const std::string &nodeip = i->first;
		// ノードID取得
		const std::string &nodeid = i->first;
		// ノードIP取得
		std::vector<std::string> vec;
		splitString(vec, nodeid, ":");
		assert(2 == vec.size());
		std::string &nodeip = vec[0];
		// ノードポート取得
		const std::string &nodeport_str = i->second;
		int nodeport = atoi(nodeport_str.c_str());

		// 重複チェック
		std::string mapkey;
		mapkey += globalStoreRecord.sourceip;
		mapkey += nodeip;
		mapkey += nodeport;
		if (sharedBlacklist.find(mapkey) == sharedBlacklist.end()) {
			// キーがない場合は通知する
			sharedBlacklist[mapkey] = globalStoreRecord.timeslot;

			// 引数作成
			CIDNNode node;
			node.ip = nodeip;
			std::stringstream ssport;
			ssport << nodeport;
			node.port = ssport.str();

			bool result = this->shareBlacklistNode(node, globalStoreRecord.sourceip, globalStoreRecord.domainid, globalStoreRecord.timeslot);
			if (!result){
				// 失敗しても共有を続ける
				TRACEP2("**** failed to share blacklist [%1%:%2%]", node.ip.c_str(), node.port.c_str());
			} else {
				TRACEP2("**** succeeded to share blacklist [%1%:%2%]", node.ip.c_str(), node.port.c_str());
			}

		} else {
			// キーがある場合は既に通知している
			TRACEP3("**** already shared blacklist [%1%][%2%:%3%]", globalStoreRecord.sourceip, nodeip, nodeport);
			continue;
		}
	}
	return true;

}

// ブラックリストを共有
// グローバルアラートの情報を指定して必要なノードに対して共有を行う
bool AlertStoreDB::shareBlacklist(GlobalStoreRecord &globalStoreRecord, std::map<std::string, unsigned long> &sharedBlacklist) {

	writelog("failed This method must not be called");
	abort();
#if 0
	// アーキテクチャを判定
	bool isBreaked = false;
	if (0 == this->m_ctx->architecture) {

		// 全ノードへ通知する 1回ずつしかリストにはないはずなので重複チェックはなし
		for (int i = 0; i < g_nodes.size(); i++) {
			CIDNNode *node = g_nodes[i];
			bool result = this->shareBlacklistNode(*node, globalStoreRecord.sourceip, globalStoreRecord.domainid, globalStoreRecord.timeslot);
			if (!result){
				// 失敗しても共有を続ける
				TRACEP2("**** failed to share blacklist [%1%:%2%]", node->ip, node->port);
			} else {
				TRACEP2("**** succeeded to share blacklist [%1%:%2%]", node->ip, node->port);
			}
		}
		return true;

	} else if (1 == this->m_ctx->architecture) {

		// どのドメインに参加しているか調べてその全てに通知する
		// ここはCSで動作するもののみ作成する P2Pはちょっと違った処理になる g_domainNodeListsを使うのでサーバでしか動きません

		// 関連するドメインIDの一覧
		std::set<std::string> domains_set;

		// 全グループをチェックする
		for (nodelistmap_type::const_iterator i = g_domainNodeLists.begin(); i != g_domainNodeLists.end(); ++i) {
			const std::string &domainid = i->first;
			std::vector <CIDNNode *> *nodelist_vec = i->second;
//TRACEP1("**** checking [%1%]", domainid);

			// ノードリストでループ
			for (int index = 0; index < nodelist_vec->size(); index++) {
				// ノードを取得
				CIDNNode *node = (*nodelist_vec)[index];

				// ノードIDをIP:PORTとして作成する
				char nodeid[NODEID_MAX];
				formatNodeID(nodeid, NODEID_MAX, node->ip.c_str(), node->port.c_str());

				if (globalStoreRecord.nodeid_set.find(nodeid) == globalStoreRecord.nodeid_set.end()) {
					// set内に存在しない
				} else {
					// set内に存在する
					// ドメインIDを保存する
					domains_set.insert(domainid);
TRACEP2("**** found [%1%][%2%]", domainid, nodeid);
					break;
				}
			}
		}

		// 関連するドメインに参加しているノードの一覧
		std::map<std::string, std::string> nodelist;

		// ドメインIDでループ
		for (std::set<std::string>::iterator its = domains_set.begin(); its != domains_set.end(); its++) {
			std::string domainid = *its;

		    // ドメインノードリストを取得
		    std::vector <CIDNNode *> *domainNodeList;
			domainNodeList = g_domainNodeLists[domainid];

			// ドメインノードリストを作成
			for (int index = 0; index < domainNodeList->size(); index++) {
		    	CIDNNode *node = (*domainNodeList)[index];

		    	// ノードIDをIP:PORTとして作成する
				char nodeid[NODEID_MAX];
				formatNodeID(nodeid, NODEID_MAX, node->ip.c_str(), node->port.c_str());
				// ノードリストに追加 重複は気にしない
				nodelist[nodeid] = node->port;
			}
		}

		TRACEP("**** start share blackllist");
		this->shareBlackListNodes(globalStoreRecord, nodelist, sharedBlacklist);
		return true;

	} else if (2 == this->m_ctx->architecture) {
		// 2ステージでは、ドメインIDをみる

		// ドメインノードリスト管理ノードに接続
		DomainListManagerDB domaindb;
		bool result = this->m_imanager->connectRemoteServer(domaindb, globalStoreRecord.domainid);
		if (!result){
			TRACEP1("**** failed to open ドメインノードリスト管理ノード [%1%]", globalStoreRecord.domainid);
			return false;
		}

		// ドメインノードリストを取得
		std::map<std::string, std::string> nodelist;
		result = domaindb.getDomainNodeList(globalStoreRecord.domainid, nodelist);
		if (!result) {
			TRACEP1("**** getDomainNodeList failed: %1%", domaindb.error().name());
			return false;
		}

		TRACEP("**** start share blackllist");
		this->shareBlackListNodes(globalStoreRecord, nodelist, sharedBlacklist);

	} else {
		abort();
	}
#endif
	return true;

}

// タイマーのコールバック
bool AlertStoreDB::checkThreshold() {

	// ローカルアラート閾値超過判定
	if (!this->checkLocalThreshold())
		return false;
	// グローバルアラート閾値超過判定
	if (!this->checkGlobalThreshold())
		return false;
	// ブラックリスト期限管理
	if (!this->checkBlacklistExpired())
		return false;

	return true;

}

// ブラックリスト期限管理
bool AlertStoreDB::checkBlacklistExpired() {

	// ***********************************************************
	// ブラックリストの期限管理を行う
	// 本来はSnortのプリプロセッサで実装しなければいけないが、実験のためにここで実装する
#if 0
	blacklist_type::iterator it = g_blacklist.begin();
	while (it != g_blacklist.end()) {
		const std::string &sourceip = it->first;
		unsigned long timeslot = it->second;
		// 保存されているタイムスロットが古かったら削除する
		if ((timeslot + this->m_ctx->blacklistLastTimeSlotSize) < this->m_ctx->current_timeslot) {
			TRACEP1("**** erase blacklist [%1%]", sourceip);
			g_blacklist.erase(it++);
		} else {
			++it;
		}
	}
	return true;
#endif

	// カーソルで全データを取得する
	kyotocabinet::GrassDB::Cursor *gcur = g_blacklist->cursor();
	gcur->jump();

	// 現在のレコードの情報
	std::string sourceip;
	std::string timeslot;

	// getで次の行に進ませないフラグ(removeで進んでしまうため)
	while (gcur->get(&sourceip, &timeslot, false)) {

		// 期限判定
		if ((atoi(timeslot.c_str()) + this->m_ctx->blacklistLastTimeSlotSize) < this->m_ctx->current_timeslot) {
			// 現在行を削除する
			gcur->remove();
			TRACEP3("delete bl current [%1%] timeslot [%2%] expire [%3%]", this->m_ctx->current_timeslot, atoi(timeslot.c_str()), this->m_ctx->blacklistLastTimeSlotSize);
		} else {
			// 削除せずに先に進む
			gcur->step();
			TRACEP3("bl current [%1%] timeslot [%2%] expire [%3%]", this->m_ctx->current_timeslot, atoi(timeslot.c_str()), this->m_ctx->blacklistLastTimeSlotSize);
		}
	}
	delete gcur;

}

// グローバルアラート閾値超過判定
bool AlertStoreDB::checkGlobalThreshold() {

	writelog("failed This method must not be called");
	abort();
	// ***********************************************************
	// global alert store

	// グローバルは全て平等に扱って累積する。設定値より古いものは削除してしまうので、次回は使われない。
#if 0
	bool logging = true;
	bool result;

	// key, value
	std::string ckey, cvalue;
	// 現在のレコードの情報
	std::string csourceip;
	unsigned long ctimeslot = 0;

	// カーソルで全データを取得する
	kyotocabinet::GrassDB::Cursor *gcur = g_gGrassDB->cursor();
	gcur->jump();

	// 現在のレコードの情報
	std::string cdomainid; // ドメインID
	std::string cnodeid; // ノードID
	ctimeslot = 0;

	std::vector <GlobalStoreRecord *> globalStoreRecords;
	GlobalStoreRecord *grecord = NULL;

	// getで次の行に進ませないフラグ(removeで進んでしまうため)
	while (gcur->get(&ckey, &cvalue, false)) {

		// データを取り出したら、DBにチェック済みのマークをつける(valueを0に変更)
		// cvalueの初期値はクライアントから渡された件数
		std::string oldvalue = std::string("0");
		if (cvalue.compare(oldvalue)) {
			// value != 0
			if (gcur->set_value(oldvalue.c_str(), oldvalue.size(), false)) {
				// success
		    } else {
		    	// failure
		      TRACEP1("$$$$ oldvalue set failed: %1%", g_gGrassDB->error().name());
		      abort();
		    }
		} else {
			// value == 0
		}

		// keyからipとtimeslotを取り出す
		std::vector<std::string> ckey_vec;
		splitString(ckey_vec, ckey, GLOBALSTORE_KEY_DELIMITER);
		assert(4 == ckey_vec.size());
		csourceip = ckey_vec[0]; // 送信元IP
		cdomainid = ckey_vec[1]; // ドメインID
		ctimeslot = atoi(ckey_vec[2].c_str()); //タイムスロット
		cnodeid = ckey_vec[3]; // ノードID

		TRACEP5("[G] key [%1%] [%2%] [%3%] [%4%] value [%5%]", ckey_vec[0], ckey_vec[1], ckey_vec[2], ckey_vec[3], cvalue);

		// 1レコード目の処理
		if (!grecord) {
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 0;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
			grecord->nodeid_set.insert(cnodeid);

			globalStoreRecords.push_back(grecord);
		}

		// ブレイクしたかどうか判定
		bool isBreaked = false;
		if (0 == this->m_ctx->architecture || 1 == this->m_ctx->architecture) {
			// 0/1では、ドメインIDをみない
			if (csourceip.compare(grecord->sourceip)) {
				isBreaked = true;
			}
		} else if (2 == this->m_ctx->architecture) {
			// 2ステージでは、ドメインIDをみる
			if (csourceip.compare(grecord->sourceip) || cdomainid.compare(grecord->domainid)) {
				isBreaked = true;
			}
		} else {
			abort();
		}

		if (isBreaked) {
			// IPかドメインIDがブレイクした
			logging && TRACEP4("[G] break ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, this->m_ctx->current_timeslot, cvalue);

			// record作成
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 1;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
			grecord->nodeid_set.insert(cnodeid);

			globalStoreRecords.push_back(grecord);

		} else {
			// 同じIP ここのログはctimeslotで 世代分ログ毎に変わるはず
			logging && TRACEP4("[G] conti ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, ctimeslot, cvalue);

			// 新しいレコードがまだない場合、このレコードが新しいか判定して設定する
			if (!grecord->isContainNewRecord) {
				grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
			}

			// カウントアップする
			grecord->count++;
		}

		// 過去レコードの削除判定
		if ((ctimeslot + this->m_ctx->globalAlertGenerationSlot) < this->m_ctx->current_timeslot) {
			// 現在行を削除する
			gcur->remove();
			// TODO ここで別の保存ストレージに移動すると後で使える
		} else {
			// 削除せずに先に進む
			gcur->step();
		}
	}
	delete gcur;

	logging = true;

	// ***********************************************************
	// 作成した配列をチェックする

	// 重複チェックMAP
	std::map<std::string, unsigned long> sharedBlacklist;

	for (int i = 0; i < globalStoreRecords.size(); i++) {

		GlobalStoreRecord *grecord = globalStoreRecords[i];

		if (grecord->timeslot < this->m_ctx->current_timeslot) {
			// 過去のtimeslot
			// removeしているので、ここにはこないはず
			logging && TRACEP1("[G] older timeslot appeared [%1%]", grecord->timeslot);
		} else if (this->m_ctx->current_timeslot < grecord->timeslot) {
			// 未来のtimeslot
			logging && TRACEP1("[G] newer timeslot appeared [%1%]", grecord->timeslot);
			if (this->m_ctx->isBatchMode) {
				// バッチではここに分岐しない
				abort();
			} else {
				// バッチじゃなければ、処理中に追加されたレコードなのでムシする
			}
		} else {
			// 処理済みのレコードのみではなかったかチェック タイムスロットはずれるので判定に使用しない
			if (grecord->isContainNewRecord) {
				// 処理済みではないレコードが存在する
				// 現在のtimeslotのレコード
				if (this->m_ctx->globalAlertThreshold < grecord->count) {
					// 閾値超過した場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold exceeded [%3%]",
							grecord->sourceip, grecord->timeslot, grecord->count);
writelog("shareBlacklist"); // log出力
					result = this->shareBlacklist(*grecord, sharedBlacklist);
				} else {
					// 閾値超過していない場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold not exceeded [%3%]",
							grecord->sourceip, grecord->timeslot, grecord->count);
				}
			} else {
				// 処理済みではないレコードが存在しない
				logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: no new record [%3%]",
						grecord->sourceip, grecord->timeslot, grecord->count);
			}
		}

	}

	// 後始末
	for (int i = 0; i < globalStoreRecords.size(); i++) {
		delete globalStoreRecords[i];
	}
#endif
	return true;
}

// ローカルアラート閾値超過判定
bool AlertStoreDB::checkLocalThreshold() {

	TRACEP1("**** timerCallback [%lu]", this->m_ctx->current_timeslot);

	bool logging = true;
	bool result;

	// ***********************************************************
	// local alert store

	// ローカルは全て平等に扱って累積する。全て削除してしまうので、次回は使われない。

	// key, value
	std::string ckey, cvalue;
	// 現在のレコードの情報
	std::string csourceip;
	unsigned long ctimeslot = 0;

	// カーソルで全データを取得する
	kyotocabinet::DB::Cursor *lcur = this->cursor();
	lcur->jump();

	std::vector <LocalStoreRecord *> localStoreRecords;
	LocalStoreRecord *lrecord = NULL;

	// getで次の行に進ませないフラグ(removeで進んでしまうため)
	while (lcur->get(&ckey, &cvalue, false)) {

		// keyからipとtimeslotを取り出す
		std::vector<std::string> vec;
		splitString(vec, ckey, LOCALSTORE_KEYDELIMITER);
		assert(3 == vec.size());
		csourceip = vec[0]; // 送信元IP
		ctimeslot = atoi(vec[1].c_str()); // タイムスロット

		// 1レコード目の処理
		if (!lrecord) {
			lrecord = new LocalStoreRecord();
			lrecord->sourceip = csourceip;
			lrecord->timeslot = this->m_ctx->current_timeslot;
			lrecord->count = 0;
			localStoreRecords.push_back(lrecord);
		}

		if (csourceip.compare(lrecord->sourceip)) {
			// IPがブレイクした
			// 同じIPであれば、タイムスロットはまとめて判定する
			logging && TRACEP3("[L] break ip [%1%]: timeslot [%2%]: value [%3%]", csourceip, this->m_ctx->current_timeslot, cvalue);

			// record作成
			lrecord = new LocalStoreRecord();
			lrecord->sourceip = csourceip;
			lrecord->timeslot = this->m_ctx->current_timeslot;
			lrecord->count = 1;
			localStoreRecords.push_back(lrecord);

		} else {
			// 同じIPのときに変更
			logging && TRACEP3("[L] conti ip [%1%]: timeslot [%2%]: value [%3%] count up", csourceip, this->m_ctx->current_timeslot, cvalue);

			// カウントアップする
			lrecord->count++;
		}

		// 現在行を削除する
		lcur->remove();
	}
	delete lcur;

	// ***********************************************************
	// 作成した配列をチェックする
	for (int i = 0; i < localStoreRecords.size(); i++) {

		LocalStoreRecord *lrecord = localStoreRecords[i];

		// 送信元IP毎に1レコードとなっている
		if (this->m_ctx->localAlertThreshold < lrecord->count) {
			// 閾値超過した場合は、global alert storeに格納する
writelog("store_global_alert"); // log出力
			logging && TRACEP3("[L] ip [%1%]: timeslot [%2%]: threshold exceeded [%3%]",
					lrecord->sourceip, lrecord->timeslot, lrecord->count);
			result = this->storeGlobalAlertData(lrecord->sourceip, lrecord->timeslot, lrecord->count);
		} else {
			// 閾値超過していない場合
			logging && TRACEP3("[L] ip [%1%]: timeslot [%2%]: threshold not exceeded [%3%]",
					lrecord->sourceip, lrecord->timeslot, lrecord->count);
		}
	}

	// 後始末
	for (int i = 0; i < localStoreRecords.size(); i++) {
		delete localStoreRecords[i];
	}

	return true;

}

// 終了処理
bool AlertStoreDB::exit() {
	// DBを閉じる
	this->close();
	return true;
}

// local alert storeにアラートを格納する
bool AlertStoreDB::storeAlert(PacketData *pdata) {

	// ブラックリストがヒットしているかをチェックする
	// 実際にはSnortのプリプロセッサでチェックする
//	if (g_blacklist.find(pdata->ip_src_str) != g_blacklist.end()) {
//writelog("blacklistHit\t%s", pdata->ip_src_str); // log出力
//		TRACEP3("**** hit blacklist [%1%][%2%:%3%]", pdata->ip_src_str, pdata->ip_dst_str, pdata->port_dst);
//	}

    if (-1 == g_blacklist->check(pdata->ip_src_str, strlen(pdata->ip_src_str))) {
    	// 一致するものがなかった場合
    } else {
    	// 一致するものがあった場合
    	writelog("blacklistHit\t%s", pdata->ip_src_str); // log出力
		TRACEP3("**** hit blacklist [%1%][%2%:%3%]", pdata->ip_src_str, pdata->ip_dst_str, pdata->port_dst);
    }

	// timestampを読めるように変換する
	char timestamp[TIMEBUF_SIZE];
	memset(timestamp, 0x00, sizeof(timestamp));
	formatTimeStampCpp(pdata->tv, timestamp);

	// 前回のタイムスロット
	static unsigned long lasttimeslot;

	// パケットのタイムスロットを取得
	unsigned long timeslot = pdata->tv->tv_sec / (this->m_ctx->localAlertTimeSlotSize * this->m_ctx->timeSlotSize);

	// 既にtimeslotが進んでしまっていたら、現在のtimeslotに入れてしまう
	if (timeslot < lasttimeslot) {
		timeslot = lasttimeslot;
	}

	// key生成
	char key[LOCALSTORE_MAXKEYSIZE];
	formatLocalAlertStoreKey(key, pdata->ip_src_str, timeslot, timestamp);

	// batch modeなら、閾値超過判定を行う
	if (this->m_ctx->isBatchMode) {
		// タイムスロットが進んでいたら、前回のタイムスロットを処理する(初回除く)
		if ((lasttimeslot < timeslot) && lasttimeslot) {
			this->checkThreshold();
		}
	}

	// local alert storeにアラートを格納する TODO 値は利用していない
	bool result = this->set(key, timestamp);
	if (!result) {
		TRACEP1("**** local alert store set failed: %1%", this->error().name());
	}

	// 今回のタイムスロットを保存
	lasttimeslot = timeslot;
	this->m_ctx->current_timeslot = lasttimeslot;
	return result;

}

// ****************************************************************************
//

// ブラックリストを共有
// グローバルアラートの情報を指定して必要なノードに対して共有を行う
bool AlertStoreDBAll::shareBlacklist(GlobalStoreRecord &globalStoreRecord, std::map<std::string, unsigned long> &sharedBlacklist) {
	// アーキテクチャを判定
	bool isBreaked = false;

	// 全ノードへ通知する 1回ずつしかリストにはないはずなので重複チェックはなし
	for (int i = 0; i < g_nodes.size(); i++) {
		CIDNNode *node = g_nodes[i];

		bool result = this->shareBlacklistNode(*node, globalStoreRecord.sourceip, globalStoreRecord.domainid, globalStoreRecord.timeslot);
		if (!result){
			// 失敗しても共有を続ける
			TRACEP2("**** failed to share blacklist [%1%:%2%]", node->ip, node->port);
		} else {
			TRACEP2("**** succeeded to share blacklist [%1%:%2%]", node->ip, node->port);
		}
	}

	return true;

}

// グローバルアラート閾値超過判定
bool AlertStoreDBAll::checkGlobalThreshold() {

	// ***********************************************************
	// global alert store

	// グローバルは全て平等に扱って累積する。設定値より古いものは削除してしまうので、次回は使われない。

	bool logging = true;
	bool result;

	// key, value
	std::string ckey, cvalue;
	// 現在のレコードの情報
	std::string csourceip;
	unsigned long ctimeslot = 0;

	// カーソルで全データを取得する
	kyotocabinet::GrassDB::Cursor *gcur = g_gGrassDB->cursor();
	gcur->jump();

	// 現在のレコードの情報
	std::string cdomainid; // ドメインID
	std::string cnodeid; // ノードID
	ctimeslot = 0;

	std::vector <GlobalStoreRecord *> globalStoreRecords;
	GlobalStoreRecord *grecord = NULL;

	// getで次の行に進ませないフラグ(removeで進んでしまうため)
	while (gcur->get(&ckey, &cvalue, false)) {

		// データを取り出したら、DBにチェック済みのマークをつける(valueを0に変更)
		// cvalueの初期値はクライアントから渡された件数
		std::string oldvalue = std::string("0");
		if (cvalue.compare(oldvalue)) {
			// value != 0
			if (gcur->set_value(oldvalue.c_str(), oldvalue.size(), false)) {
				// success
		    } else {
		    	// failure
		      TRACEP1("$$$$ oldvalue set failed: %1%", g_gGrassDB->error().name());
		      writelog("failed: oldvalue set failed");
		      abort();
		    }
		} else {
			// value == 0
		}

		// keyからipとtimeslotを取り出す
		std::vector<std::string> ckey_vec;
		splitString(ckey_vec, ckey, GLOBALSTORE_KEY_DELIMITER);
		assert(4 == ckey_vec.size());
		csourceip = ckey_vec[0]; // 送信元IP
		cdomainid = ckey_vec[1]; // ドメインID
		cnodeid = ckey_vec[2]; // ノードID
		ctimeslot = atoi(ckey_vec[3].c_str()); //タイムスロット

		TRACEP5("[G] key [%1%] [%2%] [%3%] [%4%] value [%5%]", ckey_vec[0], ckey_vec[1], ckey_vec[2], ckey_vec[3], cvalue);

		// 1レコード目の処理
		if (!grecord) {
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 0;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
//			grecord->nodeid_set.insert(cnodeid);
			grecord->nodeid = cnodeid;

			globalStoreRecords.push_back(grecord);
		}
#if 0
		// ブレイクしたかどうか判定
		bool isBreaked = false;
		if (0 == this->m_ctx->architecture || 1 == this->m_ctx->architecture) {
			// 0/1では、ドメインIDをみない
			if (csourceip.compare(grecord->sourceip)) {
				isBreaked = true;
			}
		} else if (2 == this->m_ctx->architecture) {
			// 2ステージでは、ドメインIDをみる
			if (csourceip.compare(grecord->sourceip) || cdomainid.compare(grecord->domainid)) {
				isBreaked = true;
			}
		} else {
			abort();
		}
#endif

		// ブレイクしたかどうか判定 ノード毎に判定する(ドメインIDは、ノードIDが同じなら同じ)
		if (csourceip.compare(grecord->sourceip) || cnodeid.compare(grecord->nodeid)) {
//		if (csourceip.compare(grecord->sourceip)) {
//		if (isBreaked) {
			// 送信元IPかノードIDがブレイクした
			logging && TRACEP4("[G] break ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, this->m_ctx->current_timeslot, cvalue);

			// record作成
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 1;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
//			grecord->nodeid_set.insert(cnodeid);
			grecord->nodeid = cnodeid;

			globalStoreRecords.push_back(grecord);

		} else {
			// 同じIP ここのログはctimeslotで 世代分ログ毎に変わるはず
			logging && TRACEP4("[G] conti ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, ctimeslot, cvalue);

			// 新しいレコードがまだない場合、このレコードが新しいか判定して設定する
			if (!grecord->isContainNewRecord) {
				grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
			}

			// カウントアップする
			grecord->count++;
		}

		// 過去レコードの削除判定
		if ((ctimeslot + this->m_ctx->globalAlertGenerationSlot) < this->m_ctx->current_timeslot) {
			// 現在行を削除する
			gcur->remove();
			// TODO ここで別の保存ストレージに移動すると後で使える
		} else {
			// 削除せずに先に進む
			gcur->step();
		}
	}
	delete gcur;

	logging = true;

	// ***********************************************************
	// 作成した配列をチェックする

	// 重複チェックMAP
	std::map<std::string, unsigned long> sharedBlacklist;

	for (int i = 0; i < globalStoreRecords.size(); i++) {

		GlobalStoreRecord *grecord = globalStoreRecords[i];

		if (grecord->timeslot < this->m_ctx->current_timeslot) {
			// 過去のtimeslot
			// removeしているので、ここにはこないはず
			logging && TRACEP1("[G] older timeslot appeared [%1%]", grecord->timeslot);
		} else if (this->m_ctx->current_timeslot < grecord->timeslot) {
			// 未来のtimeslot
			logging && TRACEP1("[G] newer timeslot appeared [%1%]", grecord->timeslot);
			if (this->m_ctx->isBatchMode) {
				// バッチではここに分岐しない
				writelog("failed: newer timeslot appeared");
				abort();
			} else {
				// バッチじゃなければ、処理中に追加されたレコードなのでムシする
			}
		} else {
			// 処理済みのレコードのみではなかったかチェック タイムスロットはずれるので判定に使用しない
			if (grecord->isContainNewRecord) {
				// 処理済みではないレコードが存在する
				// 現在のtimeslotのレコード
				if (this->m_ctx->globalAlertThreshold < grecord->count) {
					// 閾値超過した場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold exceeded [%3%]", grecord->sourceip, grecord->timeslot, grecord->count);
writelog("shareBlacklist"); // log出力
					result = this->shareBlacklist(*grecord, sharedBlacklist);
				} else {
					// 閾値超過していない場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold not exceeded [%3%]", grecord->sourceip, grecord->timeslot, grecord->count);
				}
			} else {
				// 処理済みではないレコードが存在しない
				logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: no new record [%3%]", grecord->sourceip, grecord->timeslot, grecord->count);
			}
		}

	}

	// 後始末
	for (int i = 0; i < globalStoreRecords.size(); i++) {
		delete globalStoreRecords[i];
	}

	return true;
}

// ****************************************************************************
//
// ブラックリストを共有
// グローバルアラートの情報を指定して必要なノードに対して共有を行う
bool AlertStoreDB1Stage::shareBlacklist(GlobalStoreRecord &globalStoreRecord, std::map<std::string, unsigned long> &sharedBlacklist) {

	// どのドメインに参加しているか調べてその全てに通知する
	// ここはCSで動作するもののみ作成する P2Pはちょっと違った処理になる g_domainNodeListsを使うのでサーバでしか動きません

	// 関連するドメインIDの一覧
	std::set<std::string> domains_set;

	// 全グループをチェックする
	for (nodelistmap_type::const_iterator i = g_domainNodeLists.begin(); i != g_domainNodeLists.end(); ++i) {
		const std::string &domainid = i->first;
		std::vector <CIDNNode *> *nodelist_vec = i->second;
//TRACEP1("**** checking [%1%]", domainid);

		// ノードリストでループ
		for (int index = 0; index < nodelist_vec->size(); index++) {
			// ノードを取得
			CIDNNode *node = (*nodelist_vec)[index];

			// ノードIDをIP:PORTとして作成する
			char nodeid[NODEID_MAX];
			formatNodeID(nodeid, NODEID_MAX, node->ip.c_str(), node->port.c_str());

			if (globalStoreRecord.nodeid.compare(nodeid)) {
				// ノードIDが等しくない
//			if (globalStoreRecord.nodeid_set.find(nodeid) == globalStoreRecord.nodeid_set.end()) {
			} else {
				// ノードIDが等しい
				// ドメインIDを保存する
				domains_set.insert(domainid);
TRACEP2("**** found [%1%][%2%]", domainid, nodeid);
				break;
			}
		}
	}

	// 関連するドメインに参加しているノードの一覧
	std::map<std::string, std::string> nodelist;

	// ドメインIDでループ
	for (std::set<std::string>::iterator its = domains_set.begin(); its != domains_set.end(); its++) {
		std::string domainid = *its;

		// ドメインノードリストを取得
		std::vector <CIDNNode *> *domainNodeList;
		domainNodeList = g_domainNodeLists[domainid];

		// ドメインノードリストを作成
		for (int index = 0; index < domainNodeList->size(); index++) {
			CIDNNode *node = (*domainNodeList)[index];

			// ノードIDをIP:PORTとして作成する
			char nodeid[NODEID_MAX];
			formatNodeID(nodeid, NODEID_MAX, node->ip.c_str(), node->port.c_str());
			// ノードリストに追加 重複は気にしない
			nodelist[nodeid] = node->port;
		}
	}
	TRACEP("**** start share blackllist");
	this->shareBlackListNodes(globalStoreRecord, nodelist, sharedBlacklist);
	return true;

}

// グローバルアラート閾値超過判定
bool AlertStoreDB1Stage::checkGlobalThreshold() {

	// ***********************************************************
	// global alert store

	// グローバルは全て平等に扱って累積する。設定値より古いものは削除してしまうので、次回は使われない。

	bool logging = true;
	bool result;

	// key, value
	std::string ckey, cvalue;
	// 現在のレコードの情報
	std::string csourceip;
	unsigned long ctimeslot = 0;

	// カーソルで全データを取得する
	kyotocabinet::GrassDB::Cursor *gcur = g_gGrassDB->cursor();
	gcur->jump();

	// 現在のレコードの情報
	std::string cdomainid; // ドメインID
	std::string cnodeid; // ノードID
	ctimeslot = 0;

	std::vector <GlobalStoreRecord *> globalStoreRecords;
	GlobalStoreRecord *grecord = NULL;

	// getで次の行に進ませないフラグ(removeで進んでしまうため)
	while (gcur->get(&ckey, &cvalue, false)) {

		// データを取り出したら、DBにチェック済みのマークをつける(valueを0に変更)
		// cvalueの初期値はクライアントから渡された件数
		std::string oldvalue = std::string("0");
		if (cvalue.compare(oldvalue)) {
			// value != 0
			if (gcur->set_value(oldvalue.c_str(), oldvalue.size(), false)) {
				// success
		    } else {
		    	// failure
		      TRACEP1("$$$$ oldvalue set failed: %1%", g_gGrassDB->error().name());
				writelog("failed: ");
		      abort();
		    }
		} else {
			// value == 0
		}

		// keyからipとtimeslotを取り出す
		std::vector<std::string> ckey_vec;
		splitString(ckey_vec, ckey, GLOBALSTORE_KEY_DELIMITER);
		assert(4 == ckey_vec.size());
		csourceip = ckey_vec[0]; // 送信元IP
		cdomainid = ckey_vec[1]; // ドメインID
		cnodeid = ckey_vec[2]; // ノードID
		ctimeslot = atoi(ckey_vec[3].c_str()); //タイムスロット

		TRACEP5("[G] key [%1%] [%2%] [%3%] [%4%] value [%5%]", ckey_vec[0], ckey_vec[1], ckey_vec[2], ckey_vec[3], cvalue);

		// 1レコード目の処理
		if (!grecord) {
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 0;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
//			grecord->nodeid_set.insert(cnodeid);
			grecord->nodeid = cnodeid;

			globalStoreRecords.push_back(grecord);
		}
#if 0
		// ブレイクしたかどうか判定
		bool isBreaked = false;
		if (0 == this->m_ctx->architecture || 1 == this->m_ctx->architecture) {
			// 0/1では、ドメインIDをみない
			if (csourceip.compare(grecord->sourceip)) {
				isBreaked = true;
			}
		} else if (2 == this->m_ctx->architecture) {
			// 2ステージでは、ドメインIDをみる
			if (csourceip.compare(grecord->sourceip) || cdomainid.compare(grecord->domainid)) {
				isBreaked = true;
			}
		} else {
			abort();
		}
#endif

		// ブレイクしたかどうか判定 ノード毎に判定する(ドメインIDは、ノードIDが同じなら同じ)
		if (csourceip.compare(grecord->sourceip) || cnodeid.compare(grecord->nodeid)) {
//		if (csourceip.compare(grecord->sourceip)) {
//		if (isBreaked) {
			// 送信元IPかノードID(ドメインIDも一意にきまる)がブレイクした
			logging && TRACEP4("[G] break ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, this->m_ctx->current_timeslot, cvalue);

			// record作成
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 1;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
//			grecord->nodeid_set.insert(cnodeid);
			grecord->nodeid = cnodeid;

			globalStoreRecords.push_back(grecord);

		} else {
			// 同じIP ここのログはctimeslotで 世代分ログ毎に変わるはず
			logging && TRACEP4("[G] conti ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, ctimeslot, cvalue);

			// 新しいレコードがまだない場合、このレコードが新しいか判定して設定する
			if (!grecord->isContainNewRecord) {
				grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
			}

			// カウントアップする
			grecord->count++;
		}

		// 過去レコードの削除判定
		if ((ctimeslot + this->m_ctx->globalAlertGenerationSlot) < this->m_ctx->current_timeslot) {
			// 現在行を削除する
			gcur->remove();
			// TODO ここで別の保存ストレージに移動すると後で使える
		} else {
			// 削除せずに先に進む
			gcur->step();
		}
	}
	delete gcur;

	logging = true;

	// ***********************************************************
	// 作成した配列をチェックする

	// 重複チェックMAP
	std::map<std::string, unsigned long> sharedBlacklist;

	for (int i = 0; i < globalStoreRecords.size(); i++) {

		GlobalStoreRecord *grecord = globalStoreRecords[i];

		if (grecord->timeslot < this->m_ctx->current_timeslot) {
			// 過去のtimeslot
			// removeしているので、ここにはこないはず
			logging && TRACEP1("[G] older timeslot appeared [%1%]", grecord->timeslot);
		} else if (this->m_ctx->current_timeslot < grecord->timeslot) {
			// 未来のtimeslot
			logging && TRACEP1("[G] newer timeslot appeared [%1%]", grecord->timeslot);
			if (this->m_ctx->isBatchMode) {
				// バッチではここに分岐しない
				writelog("failed: ");
				abort();
			} else {
				// バッチじゃなければ、処理中に追加されたレコードなのでムシする
			}
		} else {
			// 処理済みのレコードのみではなかったかチェック タイムスロットはずれるので判定に使用しない
			if (grecord->isContainNewRecord) {
				// 処理済みではないレコードが存在する
				// 現在のtimeslotのレコード
				if (this->m_ctx->globalAlertThreshold < grecord->count) {
					// 閾値超過した場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold exceeded [%3%]", grecord->sourceip, grecord->timeslot, grecord->count);
writelog("shareBlacklist"); // log出力
					result = this->shareBlacklist(*grecord, sharedBlacklist);
				} else {
					// 閾値超過していない場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold not exceeded [%3%]", grecord->sourceip, grecord->timeslot, grecord->count);
				}
			} else {
				// 処理済みではないレコードが存在しない
				logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: no new record [%3%]", grecord->sourceip, grecord->timeslot, grecord->count);
			}
		}

	}

	// 後始末
	for (int i = 0; i < globalStoreRecords.size(); i++) {
		delete globalStoreRecords[i];
	}

	return true;
}

// ****************************************************************************
//
// ブラックリストを共有
// グローバルアラートの情報を指定して必要なノードに対して共有を行う
bool AlertStoreDB2Stage::shareBlacklist(GlobalStoreRecord &globalStoreRecord, std::map<std::string, unsigned long> &sharedBlacklist) {

	// 2ステージでは、ドメインIDをみる

	// ドメインノードリスト管理ノードに接続
	DomainListManagerDB domaindb;
	bool result = this->m_imanager->connectRemoteServer(domaindb, globalStoreRecord.domainid);
	if (!result){
		TRACEP1("**** failed to open ドメインノードリスト管理ノード [%1%]", globalStoreRecord.domainid);
		return false;
	}

	// ノードが一定期間リストをキャッシュすることとしてカウントする 実験用のコード
	std::string domainlistid = globalStoreRecord.sourceip + globalStoreRecord.domainid;
	if (g_domainlists_set.find(domainlistid) == g_domainlists_set.end()) {
writelog("getDomainNodeList"); // log出力
		g_domainlists_set.insert(domainlistid);
	}

	// ドメインノードリストを取得
	std::map<std::string, std::string> nodelist;
	result = domaindb.getDomainNodeList(globalStoreRecord.domainid, nodelist);
	if (!result) {
		TRACEP1("**** getDomainNodeList failed: %1%", domaindb.error().name());
		return false;
	}

	TRACEP("**** start share blackllist");
	this->shareBlackListNodes(globalStoreRecord, nodelist, sharedBlacklist);

	return true;

}

// グローバルアラート閾値超過判定
bool AlertStoreDB2Stage::checkGlobalThreshold() {

	// ***********************************************************
	// global alert store

	// グローバルは全て平等に扱って累積する。設定値より古いものは削除してしまうので、次回は使われない。

	bool logging = true;
	bool result;

	// key, value
	std::string ckey, cvalue;
	// 現在のレコードの情報
	std::string csourceip;
	unsigned long ctimeslot = 0;

	// カーソルで全データを取得する
	kyotocabinet::GrassDB::Cursor *gcur = g_gGrassDB->cursor();
	gcur->jump();

	// 現在のレコードの情報
	std::string cdomainid; // ドメインID
	std::string cnodeid; // ノードID
	ctimeslot = 0;

	std::vector <GlobalStoreRecord *> globalStoreRecords;
	GlobalStoreRecord *grecord = NULL;

	// getで次の行に進ませないフラグ(removeで進んでしまうため)
	while (gcur->get(&ckey, &cvalue, false)) {

		// データを取り出したら、DBにチェック済みのマークをつける(valueを0に変更)
		// cvalueの初期値はクライアントから渡された件数
		std::string oldvalue = std::string("0");
		if (cvalue.compare(oldvalue)) {
			// value != 0
			if (gcur->set_value(oldvalue.c_str(), oldvalue.size(), false)) {
				// success
		    } else {
		    	// failure
		      TRACEP1("$$$$ oldvalue set failed: %1%", g_gGrassDB->error().name());
				writelog("failed: ");
		      abort();
		    }
		} else {
			// value == 0
		}

		// keyからipとtimeslotを取り出す
		std::vector<std::string> ckey_vec;
		splitString(ckey_vec, ckey, GLOBALSTORE_KEY_DELIMITER);
		assert(4 == ckey_vec.size());
		csourceip = ckey_vec[0]; // 送信元IP
		cdomainid = ckey_vec[1]; // ドメインID
		cnodeid = ckey_vec[2]; // ノードID
		ctimeslot = atoi(ckey_vec[3].c_str()); //タイムスロット

		TRACEP5("[G] key [%1%] [%2%] [%3%] [%4%] value [%5%]", ckey_vec[0], ckey_vec[1], ckey_vec[2], ckey_vec[3], cvalue);

		// 1レコード目の処理
		if (!grecord) {
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 0;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
//			grecord->nodeid_set.insert(cnodeid);
			grecord->nodeid = cnodeid;

			globalStoreRecords.push_back(grecord);
		}
#if 0
		// ブレイクしたかどうか判定
		bool isBreaked = false;
		if (0 == this->m_ctx->architecture || 1 == this->m_ctx->architecture) {
			// 0/1では、ドメインIDをみない
			if (csourceip.compare(grecord->sourceip)) {
				isBreaked = true;
			}
		} else if (2 == this->m_ctx->architecture) {
			// 2ステージでは、ドメインIDをみる
			if (csourceip.compare(grecord->sourceip) || cdomainid.compare(grecord->domainid)) {
				isBreaked = true;
			}
		} else {
			abort();
		}
#endif

		// ブレイクしたかどうか判定
		if (csourceip.compare(grecord->sourceip) || cdomainid.compare(grecord->domainid)) {
//		if (isBreaked) {
			// IPかドメインIDがブレイクした
			logging && TRACEP4("[G] break ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, this->m_ctx->current_timeslot, cvalue);

			// record作成
			grecord = new GlobalStoreRecord();
			grecord->sourceip = csourceip;
			grecord->domainid = cdomainid;
			grecord->timeslot = this->m_ctx->current_timeslot;
			grecord->count = 1;
			grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
//			grecord->nodeid_set.insert(cnodeid);
			grecord->nodeid = cnodeid;

			globalStoreRecords.push_back(grecord);

		} else {
			// 同じIP ここのログはctimeslotで 世代分ログ毎に変わるはず
			logging && TRACEP4("[G] conti ip [%1%] domainid [%2%] timeslot [%3%] value [%4%]", csourceip, cdomainid, ctimeslot, cvalue);

			// 新しいレコードがまだない場合、このレコードが新しいか判定して設定する
			if (!grecord->isContainNewRecord) {
				grecord->isContainNewRecord = (cvalue.compare(oldvalue) ? true: false);
			}

			// カウントアップする
			grecord->count++;
		}

		// 過去レコードの削除判定
		if ((ctimeslot + this->m_ctx->globalAlertGenerationSlot) < this->m_ctx->current_timeslot) {
			// 現在行を削除する
			gcur->remove();
			// TODO ここで別の保存ストレージに移動すると後で使える
		} else {
			// 削除せずに先に進む
			gcur->step();
		}
	}
	delete gcur;

	logging = true;

	// ***********************************************************
	// 作成した配列をチェックする

	// 重複チェックMAP
	std::map<std::string, unsigned long> sharedBlacklist;

	for (int i = 0; i < globalStoreRecords.size(); i++) {

		GlobalStoreRecord *grecord = globalStoreRecords[i];

		if (grecord->timeslot < this->m_ctx->current_timeslot) {
			// 過去のtimeslot
			// removeしているので、ここにはこないはず
			logging && TRACEP1("[G] older timeslot appeared [%1%]", grecord->timeslot);
		} else if (this->m_ctx->current_timeslot < grecord->timeslot) {
			// 未来のtimeslot
			logging && TRACEP1("[G] newer timeslot appeared [%1%]", grecord->timeslot);
			if (this->m_ctx->isBatchMode) {
				// バッチではここに分岐しない
				writelog("failed: ");
				abort();
			} else {
				// バッチじゃなければ、処理中に追加されたレコードなのでムシする
			}
		} else {
			// 処理済みのレコードのみではなかったかチェック タイムスロットはずれるので判定に使用しない
			if (grecord->isContainNewRecord) {
				// 処理済みではないレコードが存在する
				// 現在のtimeslotのレコード
				if (this->m_ctx->globalAlertThreshold < grecord->count) {
					// 閾値超過した場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold exceeded [%3%]",
							grecord->sourceip, grecord->timeslot, grecord->count);
writelog("shareBlacklist"); // log出力
					result = this->shareBlacklist(*grecord, sharedBlacklist);
				} else {
					// 閾値超過していない場合
					logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: threshold not exceeded [%3%]",
							grecord->sourceip, grecord->timeslot, grecord->count);
				}
			} else {
				// 処理済みではないレコードが存在しない
				logging && TRACEP3("[G] ip [%1%]: timeslot [%2%]: no new record [%3%]",
						grecord->sourceip, grecord->timeslot, grecord->count);
			}
		}

	}

	// 後始末
	for (int i = 0; i < globalStoreRecords.size(); i++) {
		delete globalStoreRecords[i];
	}

	return true;
}

// END OF FILE
