#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// C headers
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>

// C++ headers
#include <boost/lexical_cast.hpp>
#include <map>
#include <vector>
#include <sstream>

// Barnyard2 headers
#include "unified2.h"
#include "util.h"

// KyotoTycoon headers
#include <ktremotedb.h>
#include "spo_alert_cu.h"
#include "spo_alert_cu_cpp.h"
#include "spo_alert_cu_kt.h"
#include "spo_alert_cu_util.h"
#include "spo_alert_cu_interface.h"
#include "spo_alert_cu_client.h"

// KyotoTycoon headers
#include "cmdcommon.h"

#include "spo_alert_cu_kt_mod.h"

// コンパイルできないのでcmdcommon.hから移動 cmdcommon.hはexternに変更
// global variables
uint64_t g_rnd_x = 123456789;
uint64_t g_rnd_y = 362436069;
uint64_t g_rnd_z = 521288629;
uint64_t g_rnd_w = 88675123;

#include "spo_alert_cu_cpp.h"
#include "spo_alert_cu_kt.h"
#include "spo_alert_cu_util.h"

// global alert store
extern kyotocabinet::GrassDB *g_gGrassDB;
// ブラックリスト 送信元IP => ドメインID
// 検知モジュールに共有メモリ経由で渡す(未実装)
extern kyotocabinet::GrassDB *g_blacklist;
// ドメインノードリスト ドメインID => ドメインノードリスト
extern std::map<std::string, std::vector <CIDNNode *> *> g_domainNodeLists;

unsigned long g_last_blacklist_timeslot;

// Workerの実装
// **************************************************************************
  // process the join_domain procedure
  // [node] -> [domain list holder]
  RV Worker::do_join_domain(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap) {
//	TRACEP("$$$$ do_join_domain called");
    uint32_t thid = sess->thread_id();

    // ドメインID
    size_t dsiz;
    const char* dbuf = kt::strmapget(inmap, CU_MESSAGE_DOMAINID, &dsiz);
    // ノードIP
    size_t isiz;
    const char* ibuf = kt::strmapget(inmap, CU_MESSAGE_NODEIP, &isiz);
    // ノードポート
    size_t psiz;
    const char* pbuf = kt::strmapget(inmap, CU_MESSAGE_NODEPORT, &psiz);
    if (!dbuf || !ibuf || !pbuf) {
      set_message(outmap, "ERROR", "invalid parameters");
      return kt::RPCClient::RVEINVALID;
    }
    RV rv;
    opcounts_[thid][CNTSET]++;

    // ドメインノードリストを取得
    std::vector <CIDNNode *> *domainNodeList;
    if (g_domainNodeLists.find(dbuf) == g_domainNodeLists.end()) {
    	// ドメインノードリストがない場合は作成する
    	domainNodeList = new std::vector <CIDNNode *>();
    	g_domainNodeLists[dbuf] = domainNodeList;
    } else {
    	// ドメインノードリストが既にある場合
    	domainNodeList = g_domainNodeLists[dbuf];
    }

    // ドメインノードリストにノードを追加する
    // TODO 現在は重複チェックをしていない
    CIDNNode *node = new CIDNNode();
    node->ip = ibuf;
    node->port = pbuf;
    domainNodeList->push_back(node);

    set_message(outmap, "return", "OK you joined doimain[%s] Thanks", dbuf);
    rv = kt::RPCClient::RVSUCCESS;
    return rv;
  }

  // **************************************************************************
  // process the do_store_global_alert procedure
  // [node] -> [global alert store]
  RV Worker::do_store_global_alert(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap) {
	TRACEP("$$$$ do_store_global_alert called");
    uint32_t thid = sess->thread_id();

    // 送信元IP
    size_t ssiz;
    const char* sbuf = kt::strmapget(inmap, CU_MESSAGE_SOURCEIP, &ssiz);
    // ドメインIDs
    size_t dsiz;
    const char* dbuf = kt::strmapget(inmap, CU_MESSAGE_DOMAINIDS, &dsiz);
    // タイムスロット
    size_t tsiz;
    const char* tbuf = kt::strmapget(inmap, CU_MESSAGE_TIMESLOT, &tsiz);
    // 件数
    size_t csiz;
    const char* cbuf = kt::strmapget(inmap, CU_MESSAGE_COUNT, &csiz);
    // ノードID
    size_t isiz;
    const char* ibuf = kt::strmapget(inmap, CU_MESSAGE_NODEIP, &isiz);
//    if (!sbuf || !dbuf || !tbuf || !cbuf || !ibuf) {
    // ドメイン参加していない場合でも問題なくする、方がいいと思う
    if (!sbuf || !tbuf || !cbuf || !ibuf) {
      set_message(outmap, "ERROR", "invalid parameters");
      return kt::RPCClient::RVEINVALID;
    }
    RV rv;
    opcounts_[thid][CNTSET]++;

	//TRACE4("$$$$ [%1%] [%2%] [%3%] [%4%]", sbuf, dbuf, tbuf, cbuf);

	// ドメインIDはjoinされているので分割して、それぞれ格納する
	std::vector<std::string> domainids;
	splitString(domainids, dbuf, GLOBALSTORE_DOMAINS_DELIMITER);
// TODO ドメインに参加していないと情報は捨てられる
// 0を正解セットとして評価すると、これなら0でも捨てられるのでこれでいい気はするんだけど本来シナリオがよくない
//	if (0 == domainids.size()) {
//		// ドメインIDには空欄はないようにダミーを設定する
//		domainids.push_back("DUMMYID");
//	}

	for (int i = 0; i < domainids.size(); i++) {

		// キー => 値生成
	    std::string key, value;
		formatGlobalAlertStoreKey(key, value, sbuf, (domainids[i]).c_str(), tbuf, cbuf, ibuf);

		//TRACE2("$$$$ key [%1%] value [%2%]", key, value);

		// global alert storeにアラートを格納する
		if (g_gGrassDB->set(key, value)) {
	      rv = kt::RPCClient::RVSUCCESS;
	    } else {
	      TRACEP1("$$$$ do_store_global_alert set failed: %1%", g_gGrassDB->error().name());
	      rv = kt::RPCClient::RVEINTERNAL;
	    }

		// 0/1 の場合は、1件追加したら終了
		if (0 == g_ctx->architecture || 1 == g_ctx->architecture) {
			break;
		}
	}
    return rv;

  }

  // **************************************************************************
  // process the do_get_domain_node_list procedure
  // [global alert store] -> [domain list holder]
  RV Worker::do_get_domain_node_list(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap) {
	TRACEP("$$$$ do_get_domain_node_list called");
    uint32_t thid = sess->thread_id();

    // ドメインID
    size_t dsiz;
    const char* dbuf = kt::strmapget(inmap, CU_MESSAGE_DOMAINID, &dsiz);
    if (!dbuf) {
      set_message(outmap, "ERROR", "invalid parameters");
      return kt::RPCClient::RVEINVALID;
    }
    RV rv;
    opcounts_[thid][CNTSET]++;

    // 該当のドメインノードリストを取得
    std::vector <CIDNNode *> *domainNodeList;
    if (g_domainNodeLists.find(dbuf) == g_domainNodeLists.end()) {
    	// domain node list がない場合
    	TRACEP("$$$$ no domain node list in this node");
    	return kt::RPCClient::RVELOGIC;
    } else {
    	TRACEP("$$$$ domain node list found");
    	domainNodeList = g_domainNodeLists[dbuf];
    }

    // ノードの一覧を編集して戻す
    for (int i = 0; i < domainNodeList->size(); i++) {
    	CIDNNode *node = (*domainNodeList)[i];

    	// キーをユニークにする必要があるので、ノードIDをIP:PORTとして作成する
    	char nodeid[NODEID_MAX];
    	formatNodeID(nodeid, NODEID_MAX, node->ip.c_str(), node->port.c_str());
        set_message(outmap, nodeid, node->port.c_str()); // 値はとりあえずポートとしておくが値は必要はない
    	//TRACE2("$$$$ list item ip [%1%] port [%2%]", node->ip.c_str(), node->port.c_str());
    }

	rv = kt::RPCClient::RVSUCCESS;
	return rv;
  }

  // **************************************************************************
  // process the do_share_blacklist procedure
  // [domain list holder] -> [node]
  RV Worker::do_share_blacklist(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap) {
	TRACEP("$$$$ do_share_blacklist called");
    uint32_t thid = sess->thread_id();

    // 送信元IP
    size_t ssiz;
    const char* sbuf = kt::strmapget(inmap, CU_MESSAGE_SOURCEIP, &ssiz);
    // ドメインID
    size_t dsiz;
    const char* dbuf = kt::strmapget(inmap, CU_MESSAGE_DOMAINID, &dsiz);
    // タイムスロット
    size_t tsiz;
    const char* tbuf = kt::strmapget(inmap, CU_MESSAGE_TIMESLOT, &tsiz);
    if (!sbuf || !dbuf || !tbuf) {
      set_message(outmap, "ERROR", "invalid parameters");
      return kt::RPCClient::RVEINVALID;
    }
    RV rv;
    opcounts_[thid][CNTSET]++;

    set_message(outmap, "return", "OK got source ip [%s] domainid [%s] Thanks", sbuf, dbuf);

    // ブラックリストに突っ込む
    // TODO どのドメインに対してのブラックリストかはとりあえず捨てることにした
    // 期限管理のためにタイムスロットを保存(上書き)することにする
#if 0
    if (g_blacklist.find(sbuf) == g_blacklist.end()) {
    	// 一致するものがなかった場合
    	g_blacklist[sbuf] = boost::lexical_cast<unsigned long>(tbuf);
    	TRACEP1("$$$$ new blacklist entry created [%1%]", sbuf);
    } else {
    	// 一致するものがあった場合
    	g_blacklist[sbuf] = boost::lexical_cast<unsigned long>(tbuf);
    	TRACEP1("$$$$ exist blacklist entry updated [%1%]", sbuf);
    }
#endif

    if (-1 == g_blacklist->check(sbuf, ssiz)) {
    	// 一致するものがなかった場合
    	TRACEP1("$$$$ new blacklist entry created [%1%]", sbuf);
    } else {
    	// 一致するものがあった場合
    	TRACEP1("$$$$ exist blacklist entry updated [%1%]", sbuf);
    }
    std::string key(sbuf);
    std::string value(tbuf);
	g_blacklist->set(key, value);

	// 最新のブラックリスト更新タイムスロットを保存
	g_last_blacklist_timeslot = g_ctx->current_timeslot;

    rv = kt::RPCClient::RVSUCCESS;
	return rv;
  }

  // **************************************************************************
  // process the do_cu_status procedure
  // test
  RV Worker::do_cu_status(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap) {
	TRACEP("$$$$ do_cu_status called");
    uint32_t thid = sess->thread_id();
    RV rv;
    opcounts_[thid][CNTSET]++;

    // ここで処理
    set_message(outmap, "return", "STATUS");

    // ドメインノードリストを出力
	set_message(outmap, "", "domain node lists");
	std::map<std::string, std::vector <CIDNNode *> *>::iterator it = g_domainNodeLists.begin();
    while(it != g_domainNodeLists.end()) {
		const std::string &domainid = (*it).first;
		std::vector <CIDNNode *> *domainNodeList = (*it).second;
    	set_message(outmap, "", "domain id [%s] list", domainid.c_str());
	    for (int i = 0; i < domainNodeList->size(); i++) {
	    	CIDNNode *node = (*domainNodeList)[i];
	    	set_message(outmap, "", "[#%03d] ip [%s] port [%d]", i, node->ip.c_str(), node->port.c_str());
	    }
		++it;
    }
    // ローカルアラートを出力? TODO
    // グローバルアラートを出力? TODO

    rv = kt::RPCClient::RVSUCCESS;
    return rv;
  }


  // **************************************************************************
  // process the do_get_blacklist procedure
  // [detection] -> [domain list holder]
  RV Worker::do_get_blacklist(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap) {
	TRACEP("$$$$ do_get_blacklist called");
    uint32_t thid = sess->thread_id();

    // シリアル番号
    size_t ssiz;
    const char* sbuf = kt::strmapget(inmap, CU_MESSAGE_SERIALNO, &ssiz);
    if (!sbuf) {
      set_message(outmap, "ERROR", "invalid parameters");
      return kt::RPCClient::RVEINVALID;
    }
    RV rv;
    opcounts_[thid][CNTSET]++;

    // シリアル番号 引数
    std::stringstream ss;
    unsigned long serialno;
    ss << sbuf;
	ss >> serialno;

	// シリアル番号 最新
	ss.clear();
	ss.str("");
	ss << g_last_blacklist_timeslot;

    if (serialno < g_last_blacklist_timeslot) {
    	TRACEP1("$$$$ dump blacklist [%1%]", sbuf);

    	// シリアル番号
        set_message(outmap, CU_MESSAGE_SERIALNO, ss.str().c_str());

        // ブラックリストを編集して戻す
    	std::string ckey, cvalue;
    	kyotocabinet::GrassDB::Cursor *gcur = g_blacklist->cursor();
    	gcur->jump();
    	while (gcur->get(&ckey, &cvalue, true)) {
        	TRACEP2("$$$$ blacklist [%1%][%2%]", ckey, cvalue);
            set_message(outmap, ckey.c_str(), cvalue.c_str());
    	}
    	delete gcur;
    } else {
    	// 更新されていなければ、空で返す
    	TRACEP1("$$$$ no new blacklist [%1%]", sbuf);
    }

	rv = kt::RPCClient::RVSUCCESS;
	return rv;
  }
