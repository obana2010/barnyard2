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

// KyotoTycoon headers
//#include "cmdcommon.h"
#include <ktremotedb.h>
#include "spo_alert_cu.h"
#include "spo_alert_cu_cpp.h"
#include "spo_alert_cu_kt.h"
#include "spo_alert_cu_util.h"
#include "spo_alert_cu_interface.h"
#include "spo_alert_cu_client.h"

// ****************************************************************************
// クライアントクラス

// ブラックリスト共有
bool NodeBlacklistDB::shareBlacklist(
		  const char *sbuf, size_t ssiz,
		  const char *dbuf, size_t dsiz,
		  unsigned long timeslot
		  ) {
	_assert_(dbuf && dsiz <= kc::MEMMAXSIZ && sbuf && ssiz <= kc::MEMMAXSIZ);
	std::map<std::string, std::string> inmap;

	set_sig_param(inmap);
	set_db_param(inmap);
	inmap[CU_MESSAGE_SOURCEIP] = std::string(sbuf, ssiz); // ソースIP
	inmap[CU_MESSAGE_DOMAINID] = std::string(dbuf, dsiz); // ドメインID
	std::ostringstream stimeslot;
	stimeslot << timeslot;
	inmap[CU_MESSAGE_TIMESLOT] = std::string(stimeslot.str()); // タイムスロット

	std::map<std::string, std::string> outmap;
	kyototycoon::RPCClient::ReturnValue rv = rpc_.call(CU_METHOD_SHARE_BLACKLIST, &inmap, &outmap);
	if (rv != kyototycoon::RPCClient::RVSUCCESS) {
	  set_rpc_error(rv, outmap);
	  return false;
	}
	return true;

}

// ブラックリスト共有ラッパ
bool NodeBlacklistDB::shareBlacklist(const std::string &sourceip, const std::string &domainid, unsigned long timeslot) {

	return this->shareBlacklist(sourceip.c_str(), sourceip.size(), domainid.c_str(), domainid.size(), timeslot);

}

// ****************************************************************************
// ドメインノードリスト取得
bool DomainListManagerDB::getDomainNodeList(const char* dbuf, size_t dsiz, std::map<std::string, std::string> &outmap) {

	_assert_(dbuf && dsiz <= kc::MEMMAXSIZ);
//writelog("getDomainNodeList"); // log出力
	std::map<std::string, std::string> inmap;

	set_sig_param(inmap);
	set_db_param(inmap);
	inmap[CU_MESSAGE_DOMAINID] = std::string(dbuf, dsiz); // ドメインID

	//std::map<std::string, std::string> outmap;
	kyototycoon::RPCClient::ReturnValue rv = rpc_.call(CU_METHOD_GET_DOMAIN_NODE_LIST, &inmap, &outmap);
	if (rv != kyototycoon::RPCClient::RVSUCCESS) {
	  set_rpc_error(rv, outmap);
	  return false;
	}

	return true;

}
// ドメインノードリスト取得ラッパ
bool DomainListManagerDB::getDomainNodeList(const std::string& domainid, std::map<std::string, std::string> &outmap) {
	_assert_(true);
	return this->getDomainNodeList(domainid.c_str(), domainid.size(), outmap);
}

// ****************************************************************************
// global alert store client
bool GlobalAlertStoreDB::storeGlobalAlert(const char* sbuf, size_t ssiz, const char* dbuf, size_t dsiz, const unsigned int timeslot, const unsigned long count, const char* ibuf, size_t isiz) {
	_assert_(kbuf && ksiz <= kc::MEMMAXSIZ && vbuf && vsiz <= kc::MEMMAXSIZ && ibuf && isiz <= kc::MEMMAXSIZ);
	std::map<std::string, std::string> inmap;

	set_sig_param(inmap);
	set_db_param(inmap);
	inmap[CU_MESSAGE_SOURCEIP] = std::string(sbuf, ssiz); // ソースIP
	inmap[CU_MESSAGE_DOMAINIDS] = std::string(dbuf, dsiz); // ドメインID
	std::ostringstream stimeslot;
	stimeslot << timeslot;
	inmap[CU_MESSAGE_TIMESLOT] = std::string(stimeslot.str()); // タイムスロット
	std::ostringstream scount;
	scount << count;
	inmap[CU_MESSAGE_COUNT] = std::string(scount.str()); // 件数
	inmap[CU_MESSAGE_NODEIP] = std::string(ibuf, isiz); // ノードID

	std::map<std::string, std::string> outmap;
	kyototycoon::RPCClient::ReturnValue rv = rpc_.call(CU_METHOD_STORE_GLOBAL_ALERT, &inmap, &outmap);
	if (rv != kyototycoon::RPCClient::RVSUCCESS) {
	  set_rpc_error(rv, outmap);
	  return false;
	}
	return true;
}

// ラッパ
bool GlobalAlertStoreDB::storeGlobalAlert(const std::string& sourceip, const std::string& domainids, const unsigned long timeslot, const unsigned long count, const std::string& nodeid) {
	_assert_(true);
	return this->storeGlobalAlert(sourceip.c_str(), sourceip.size(), domainids.c_str(), domainids.size(), timeslot, count, nodeid.c_str(), nodeid.size());
}

// ラッパ
bool GlobalAlertStoreDB::storeGlobalAlert(const std::string& sourceip, const std::vector<std::string>& domainids_vec, const unsigned long timeslot, const unsigned long count, const std::string& nodeid) {
	_assert_(true);

	// vectorのstringをjoinして、ドメインを一つの引数にする。
	std::stringstream ss;
	for(size_t i = 0; i < domainids_vec.size(); i++) {
		if(i != 0) {
			ss << GLOBALSTORE_DOMAINS_DELIMITER;
		}
		ss << domainids_vec[i];
	}
	std::string domainids = ss.str();

	return this->storeGlobalAlert(sourceip, domainids, timeslot, count, nodeid);
}

// ****************************************************************************

// ドメイン参加要求クライアント
bool DomainListManagerDB::joinDomain(const char* dbuf, size_t dsiz, const char* ibuf, size_t isiz, const char* pbuf, size_t psiz) {

	_assert_(dbuf && dsiz <= kc::MEMMAXSIZ && ibuf && isiz <= kc::MEMMAXSIZ && pbuf && psiz <= kc::MEMMAXSIZ);
	std::map<std::string, std::string> inmap;
	set_sig_param(inmap);
	set_db_param(inmap);
	inmap[CU_MESSAGE_DOMAINID] = std::string(dbuf, dsiz); // ドメインID
	inmap[CU_MESSAGE_NODEIP] = std::string(ibuf, isiz); // ノードIP
	inmap[CU_MESSAGE_NODEPORT] = std::string(pbuf, psiz); // ノードポート
	std::map<std::string, std::string> outmap;
	kyototycoon::RPCClient::ReturnValue rv = rpc_.call(CU_METHOD_JOIN_DOMAIN, &inmap, &outmap);
	if (rv != kyototycoon::RPCClient::RVSUCCESS) {
	  set_rpc_error(rv, outmap);
	  return false;
	}
	return true;

}

// ドメイン参加要求クライアントラッパ
bool DomainListManagerDB::joinDomain(const std::string& domainid, const std::string& nodeip, const std::string& nodeport) {

	_assert_(true);
	return this->joinDomain(domainid.c_str(), domainid.size(), nodeip.c_str(), nodeip.size(), nodeport.c_str(), nodeport.size());

}

// END OF FILE

