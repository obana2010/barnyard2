#ifndef __SPO_ALERT_CU_INTERFACE_H__
#define __SPO_ALERT_CU_INTERFACE_H__

class iAlertStoreDB;
class iCIDNManager;

// storeAlertの引数
struct PacketData {
	PacketCpp *p;
	char *ip_src_str;
	int port_src;
	char *ip_dst_str;
	int port_dst;
	timeval *tv;
};

// アラート蓄積のインターフェイス(抽象クラス)
class iAlertStoreDB {
protected:
	SpoAlertCuData *m_ctx;
public:
	iAlertStoreDB(SpoAlertCuData *ctx);
	virtual ~iAlertStoreDB();

	virtual bool init() = 0;
	virtual bool exit() = 0;
	virtual bool storeAlert(PacketData *pdata) = 0;
	virtual bool checkThreshold() = 0;
};

// コントローラのインターフェイス(抽象クラス)
class iCIDNManager {
protected:
	SpoAlertCuData *m_ctx;
	iAlertStoreDB *m_ildb;
public:
	iCIDNManager(SpoAlertCuData *ctx) {
		this->m_ctx = ctx;
	}
	virtual ~iCIDNManager() {
	}

	virtual bool init() = 0;
	virtual bool exit() = 0;
	virtual bool joinCIDN() = 0;
	virtual bool setTimer() = 0;
	virtual bool timerCallback() = 0;
	virtual bool storeAlert(PacketData *pdata) = 0;
};

#endif  /* __SPO_ALERT_CU_INTERFACE_H__ */
