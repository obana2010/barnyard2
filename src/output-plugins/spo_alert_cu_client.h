#ifndef __SPO_ALERT_CU_CLIENT_H__
#define __SPO_ALERT_CU_CLIENT_H__

#include <spo_alert_cu_interface.h>

class NodeBlacklistDB;
class DomainListManagerDB;
class GlobalAlertStoreDB;
class AlertStoreDB;
class AlertStoreDB1Stage;
class AlertStoreDB2Stage;
class AlertStoreDB2All;
class CIDNManagerImpl;
class CIDNManager2Stage;

// ****************************************************************************
// ブラックリスト共有クラス
class NodeBlacklistDB: public kyototycoon::RemoteDB {
public:
	explicit NodeBlacklistDB() : kyototycoon::RemoteDB() {
	}
	virtual ~NodeBlacklistDB() {
	}

  // ブラックリストを共有する
public:
  bool shareBlacklist(const std::string &sourceip, const std::string &domainid, unsigned long timeslot);
protected:
  bool shareBlacklist(const char *sbuf, size_t ssiz, const char *dbuf, size_t dsiz, unsigned long timeslot);
};

// ****************************************************************************
// ドメインノードリスト管理ノード
class DomainListManagerDB: public kyototycoon::RemoteDB {
public:
	explicit DomainListManagerDB() : kyototycoon::RemoteDB() {
	}
	virtual ~DomainListManagerDB() {
	}

	// ドメインに参加する
public:
	bool joinDomain(const std::string& domainid, const std::string& nodeip, const std::string& nodeport);
protected:
	bool joinDomain(const char* dbuf, size_t dsiz, const char* ibuf, size_t isiz, const char* pbuf, size_t psiz);

	// ドメインノードリストを取得する
public:
	bool getDomainNodeList(const std::string& domainid, std::map<std::string, std::string> &outmap);
protected:
	bool getDomainNodeList(const char* dbuf, size_t dsiz, std::map<std::string, std::string> &outmap);
};

// ****************************************************************************
// グローバルアラートストア
class GlobalAlertStoreDB: public kyototycoon::RemoteDB {
public:
	explicit GlobalAlertStoreDB() : kyototycoon::RemoteDB() {
	}
	virtual ~GlobalAlertStoreDB() {
	}

  // グローバルアラートストアに蓄積する
  bool storeGlobalAlert(const std::string& sourceip, const std::string& domainids, const unsigned long timeslot, const unsigned long count, const std::string& nodeip);
  bool storeGlobalAlert(const std::string& sourceip, const std::vector<std::string>& domainids_vec, const unsigned long timeslot, const unsigned long count, const std::string& nodeip);
protected:
  bool storeGlobalAlert(const char* sbuf, size_t ssiz, const char* dbuf, size_t dsiz, const unsigned int timeslot, const unsigned long count, const char* ibuf, size_t isiz);
};

// ****************************************************************************
// local alert store構造体
struct LocalStoreRecord {
	std::string sourceip; // 送信元IP
	unsigned long timeslot; // タイムスロット
	unsigned long count; // レコード数
};

// global alert store構造体
struct GlobalStoreRecord {
	std::string sourceip; // 送信元
	std::string domainid; // ドメインID
	unsigned long timeslot; // タイムスロット
	unsigned long count; // レコード数
	bool isContainNewRecord; // 処理済みではないレコードを含むか？
//	std::set <std::string> nodeid_set; // 廃止予定
	std::string nodeid; // ノードID
};

// ****************************************************************************
// ローカルアラートストア
class AlertStoreDB: public kyotocabinet::GrassDB, public iAlertStoreDB {
protected:
	CIDNManagerImpl *m_imanager;
public:
	explicit AlertStoreDB(SpoAlertCuData *ctx, CIDNManagerImpl *imanager) : kyotocabinet::GrassDB() , iAlertStoreDB(ctx) {
		this->m_imanager = imanager;
		return;
	}
	virtual ~AlertStoreDB() {
		return;
	}

	// 実装メソッド
	virtual bool init();
	virtual bool exit();
	virtual bool storeAlert(PacketData *pdata);
	virtual bool checkThreshold();

	// 独自メソッド
	bool storeGlobalAlertData(const std::string &sourceip, const unsigned long timeslot, unsigned long counter);

protected:
	  virtual bool checkLocalThreshold();
	  virtual bool checkGlobalThreshold();
	  virtual bool checkBlacklistExpired();
	  virtual bool shareBlacklist(
			  GlobalStoreRecord &globalStoreRecord,
			  std::map<std::string, unsigned long> &sharedBlacklist);
	  virtual bool shareBlacklistNode(
			  CIDNNode &node,
			  std::string &sourceip,
			  std::string &domainid,
			  unsigned long timeslot);
	  bool shareBlackListNodes(
			GlobalStoreRecord &globalStoreRecord,
			std::map<std::string, std::string> nodelist,
			std::map<std::string, unsigned long> &sharedBlacklist);
};

// ****************************************************************************
// ローカルアラートストア 全ノード共有モデル
class AlertStoreDBAll: public AlertStoreDB {
public:
	explicit AlertStoreDBAll(SpoAlertCuData *ctx, CIDNManagerImpl *imanager) : AlertStoreDB(ctx, imanager) {
		return;
	}
	virtual ~AlertStoreDBAll() {
		return;
	}

protected:
  virtual bool shareBlacklist(
		  GlobalStoreRecord &globalStoreRecord,
		  std::map<std::string, unsigned long> &sharedBlacklist);
  virtual bool checkGlobalThreshold();
};

// ****************************************************************************
// ローカルアラートストア 全ドメイン共有モデル
class AlertStoreDB1Stage: public AlertStoreDB {
public:
	explicit AlertStoreDB1Stage(SpoAlertCuData *ctx, CIDNManagerImpl *imanager) : AlertStoreDB(ctx, imanager) {
		return;
	}
	virtual ~AlertStoreDB1Stage() {
		return;
	}

protected:
	virtual bool shareBlacklist(GlobalStoreRecord &globalStoreRecord, std::map<std::string, unsigned long> &sharedBlacklist);
	virtual bool checkGlobalThreshold();
};

// ****************************************************************************
//// ローカルアラートストア 特定ドメイン共有モデル
class AlertStoreDB2Stage: public AlertStoreDB {
public:
	explicit AlertStoreDB2Stage(SpoAlertCuData *ctx, CIDNManagerImpl *imanager) : AlertStoreDB(ctx, imanager) {
		return;
	}
	virtual ~AlertStoreDB2Stage() {
		return;
	}
protected:
	virtual bool shareBlacklist(GlobalStoreRecord &globalStoreRecord, std::map<std::string, unsigned long> &sharedBlacklist);
	virtual bool checkGlobalThreshold();
};

// ****************************************************************************
// 情報共有モデル用CIDNマネージャ
class CIDNManagerImpl: public iCIDNManager {
public:
	static CIDNManagerImpl *m_imanager;
	CIDNManagerImpl(SpoAlertCuData *ctx);
	virtual ~CIDNManagerImpl();

	// 実装メソッド
	virtual bool init();
	virtual bool exit();
	virtual bool joinCIDN();
	virtual bool setTimer();
	virtual bool timerCallback();
	virtual bool storeAlert(PacketData *pdata);

	// 独自メソッド
	static void timerCallback(int signum);
	virtual bool connectRemoteServer(kyototycoon::RemoteDB &client, std::string &id_str);
protected:
	virtual bool getRemoteServer(const char *id, char *ip, size_t ipsize, int *port);
};

// ****************************************************************************
// 全ノード共有モデル用CIDNマネージャ
class CIDNManagerAll: public CIDNManagerImpl {
public:
	CIDNManagerAll(SpoAlertCuData *ctx);
	virtual ~CIDNManagerAll();

	// 実装メソッド
	virtual bool init();

protected:
//	virtual bool getRemoteServer(const char *id, char *ip, size_t ipsize, int *port);
};

// ****************************************************************************
// 全ドメイン共有モデル用CIDNマネージャ
class CIDNManager1Stage: public CIDNManagerImpl {
public:
	CIDNManager1Stage(SpoAlertCuData *ctx);
	virtual ~CIDNManager1Stage();

	// 実装メソッド
	virtual bool init();

protected:
//	virtual bool getRemoteServer(const char *id, char *ip, size_t ipsize, int *port);
};

// ****************************************************************************
// 2ステージ情報共有モデル用CIDNマネージャ
class CIDNManager2Stage: public CIDNManagerImpl {
public:
	CIDNManager2Stage(SpoAlertCuData *ctx);
	virtual ~CIDNManager2Stage();

	// 実装メソッド
	virtual bool init();

protected:
//	virtual bool getRemoteServer(const char *id, char *ip, size_t ipsize, int *port);
};

// ****************************************************************************

#endif  /* __SPO_ALERT_CU_CLIENT_H__ */
