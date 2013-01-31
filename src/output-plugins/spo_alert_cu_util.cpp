// **************************************************************************
// include headers

// C headers
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/sha.h>

// Barnyard2 headers
extern "C" {
#include "unified2.h"
#include "util.h"
//#include "log_text.h" CANNOT COMPILE
//#include "sf_textlog.h" CANNOT COMPILE
//#include "barnyard2.h" CANNOT COMPILE
}

#include "spo_alert_cu.h"
#include "spo_alert_cu_cpp.h"
#include "spo_alert_cu_util.h"

// コンテキスト
extern SpoAlertCuData *g_ctx;

// タイムスタンプを作成する
void formatTimeStampLog(char *timestamp, size_t size) {

	// タイムスタンプ作成
	time_t timer;
	time(&timer);
	struct tm *lt = localtime(&timer);
	snprintf(timestamp, size, "%02d/%02d/%02d-%02d:%02d:%02d",
			lt->tm_year - 100, lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);

}

// 実験のためのログを出力する
void writelog(const char *format, char *value1) {

	char buf[1024];
	snprintf(buf, sizeof(buf), format, value1);
	writelog(buf);

}

// 実験のためのログを出力する
void writelog(const char *format, char *value1, char *value2) {

	char buf[1024];
	snprintf(buf, sizeof(buf), format, value1, value2);
	writelog(buf);

}

// 実験のためのログを出力する
void writelog(const char *message) {

	// オープンのチェック
	assert(g_ctx);
	assert(g_ctx->confcpp);
	assert(((ConfCpp *)(g_ctx->confcpp))->logfs);

	// タイムスタンプ作成
	char timestamp[100];
//	time_t timer;
//	time(&timer);
//    struct tm *lt = localtime(&timer);
//    sprintf(timestamp, "%02d/%02d/%02d-%02d:%02d:%02d",
//    		lt->tm_year - 100, lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);

	formatTimeStampLog(timestamp, sizeof(timestamp));

    // 出力
    ConfCpp *confcpp = (ConfCpp *)(g_ctx->confcpp);
	*(confcpp->logfs) << timestamp << "\t" << message << std::endl;

}
void formatNodeID(char *nodeid, size_t nodeidsize, const char *nodeip, const char *nodeport) {

	snprintf(nodeid, nodeidsize, "%s:%s", nodeip, nodeport);

}

// local alert storeのkey生成
void formatLocalAlertStoreKey(
		char *key,
		const char *sourceip,
		unsigned long timeslot,
		const char *timestamp) {

	snprintf(key,
			LOCALSTORE_MAXKEYSIZE,
			"%s" LOCALSTORE_KEYDELIMITER "%ld" LOCALSTORE_KEYDELIMITER "%s",
			sourceip,
			timeslot,
			timestamp);

}

// global alert storeのkey生成
void formatGlobalAlertStoreKey(
		std::string &key,
		std::string &value,
		const char *sourceip,
		const char *domainid,
		const char *timeslot,
		const char *count,
		const char *nodeid) {

	// 送信元IP、ドメインID、ノードID、タイムスロット
	// キーを作成
	key = sourceip;
	key += GLOBALSTORE_KEY_DELIMITER;
	key += domainid;
	key += GLOBALSTORE_KEY_DELIMITER;
	key += nodeid;
	key += GLOBALSTORE_KEY_DELIMITER;
	key += timeslot;

	// 値を作成
	value = count;

}

// 文字列からIDを求める
int getIDfromChar(const char *idseed_str, char *id_str) {

	assert(idseed_str);
	assert(id_str);

	// バイナリで格納 20byte
	unsigned char work[SHA_DIGEST_LENGTH];

	// ハッシュを求める
	unsigned long idseed_len = strlen(idseed_str);
	SHA1((const unsigned char *)idseed_str, idseed_len, work);
	//unsigned char *buf = SHA1((const unsigned char *)idseed_str, idseed_len, NULL);

char tmp[4];
::memset((void *)tmp, 0x00, sizeof(tmp));
std::string str;

//printf("[");
for (int hexdump_i = 0; hexdump_i < SHA_DIGEST_LENGTH; hexdump_i++){
	sprintf(tmp, "%02X", *(work + hexdump_i));
	str.append(tmp);
}
//printf("]\n");
	strncpy(id_str, str.c_str(), SHA_DIGEST_LENGTH * 2);

	return 1;

}

// 文字列からIDを求める
int getIDfromStr(const char *idseed_str, std::string &id_str) {

	// 文字列で格納 40byte
	char md[(SHA_DIGEST_LENGTH * 2) + 1];
	::memset((void *)md, 0x00, sizeof(md));
	int result = getIDfromChar(idseed_str, md);
	if (result) {
		id_str.assign(md);
	} else {
		abort();
	}
	return result;

}

// YAMLを構造体にインポートする
void operator >> (const YAML::Node &ynode, CIDNNode &node) {
   ynode["name"] >> node.name;
   ynode["ip"] >> node.ip;
   ynode["port"] >> node.port;
}

// ログファイルをオープンする
void openLogFile(const char *logfile, SpoAlertCuData *ctx, std::map<std::string, std::string> *conf) {

	// ファイルオープン
	std::ofstream *logfs = new std::ofstream(logfile);
	ConfCpp *confcpp = (ConfCpp *)(ctx->confcpp);
	if (!confcpp) {
		std::cout << "**** confcpp is NULL" << std::endl;
	}
	confcpp->logfs = logfs;

	// グローバルに設定しないとこれを呼び出す全てのソースでCのヘッダをインクルードするはめになる。。。
	g_ctx = ctx;

}

// ノードリストのYAMLを読み込む
void getNodeListFile(const char *nodelistfile, SpoAlertCuData *ctx, std::map<std::string, std::string> *conf) {

	std::map<std::string, std::string> *nodelist = new std::map<std::string, std::string>();

	try{
		std::ifstream finnode(nodelistfile);

		YAML::Parser parser(finnode);
		YAML::Node doc;
		parser.GetNextDocument(doc);

		CHECK_YAML(doc, Sequence);
        for (unsigned i = 0; i < doc.size(); i++) {
    		CHECK_YAML(doc[i], Map);
        	for (YAML::Iterator itr(doc[i].begin()), end(doc[i].end()); itr != end; ++itr) {
                const YAML::Node &key   = itr.first();
                const YAML::Node &value = itr.second();
        		CHECK_YAML(key, Scalar);
                std::string key_str;
                key >> key_str;
				std::cerr << "key_str [" << key_str << "]\n";

                // ノードリスト (設定ファイルで与える場合)
                if (!key_str.compare("nodes")) {
					std::cerr << "nodes list\n";
	        		CHECK_YAML(value, Sequence);
                    for (unsigned j = 0; j < value.size(); j++) {
                    	CIDNNode *node = new CIDNNode();
		        		CHECK_YAML(value[j], Map);
						value[j] >> *node;
						if (!node->name.compare("S")) {
							// communication unit
							(*conf)["cktport"] = node->port;
							ctx->icktport = atoi(node->port.c_str());
							strncpy(ctx->cktip, node->ip.c_str(), IP_ADDRESS_STRING_MAX);
							strncpy(ctx->cktport, node->port.c_str(), PORT_STRING_MAX);
							std::cerr << "communication ip [" << node->ip << "] port [" << node->port << "]\n";
						} else {
							g_nodes.push_back(node);
							std::cerr << "node ip [" << node->ip << "] port [" << node->port << "]\n";
						}
                	}
                } else

                // unknown
                {
					TRACE1("unknown key[%1%]\n", key_str.c_str());
					abort();
                }
    		}
        }

	} catch(YAML::Exception &e) {
		TRACE1("error:%1%\n", e.what());
		abort();
	}

	if (0 == g_nodes.size()) {
		TRACE("nodelistfile incomplete!\n");
		abort();
	}

}

// YAMLを読み込む
extern "C"
void getConfFile(const char *conffile, SpoAlertCuData *ctx) {

	std::map<std::string, std::string> *conf = new std::map<std::string, std::string>();
	ctx->conf = (void *)conf;
	// Cpp用
	ctx->confcpp = (void *)new ConfCpp();

	// 初期値
	ctx->localAlertTimeSlotSize = -1;
    ctx->localAlertThreshold = -1;
    ctx->globalAlertTimeSlotSize = -1;
    ctx->globalAlertThreshold = -1;
    ctx->globalAlertGenerationSlot = -1;
    ctx->blacklistLastTimeSlotSize = -1;

    ctx->fakeData = 1; // true

	try{
		std::ifstream finconf(conffile);

		YAML::Parser parser(finconf);
		YAML::Node doc;
		parser.GetNextDocument(doc);

		CHECK_YAML(doc, Sequence);
        for (unsigned i = 0; i < doc.size(); i++) {
    		CHECK_YAML(doc[i], Map);
        	for (YAML::Iterator itr(doc[i].begin()), end(doc[i].end()); itr != end; ++itr) {
                const YAML::Node &key   = itr.first();
                const YAML::Node &value = itr.second();
        		CHECK_YAML(key, Scalar);
                std::string key_str;
                key >> key_str;
				std::cerr << "key_str [" << key_str << "]\n";

                // ノードリスト (設定ファイルで与える場合)
                if (!key_str.compare("nodes")) {
    				/*
					std::cerr << "nodes list\n";
	        		CHECK_YAML(value, Sequence);
                    for (unsigned j = 0; j < value.size(); j++) {
                    	CIDNNode *node = new CIDNNode();
		        		CHECK_YAML(value[j], Map);
						value[j] >> *node;
						if (!node->name.compare("S")) {
							// communication unit
							(*conf)["cktport"] = node->port;
							ctx->icktport = atoi(node->port.c_str());
							strncpy(ctx->cktip, node->ip.c_str(), IP_ADDRESS_STRING_MAX);
							strncpy(ctx->cktport, node->port.c_str(), PORT_STRING_MAX);
							std::cerr << "communication ip [" << node->ip << "] port [" << node->port << "]\n";
						} else if (!node->name.compare("D")){
							// detection unit
							(*conf)["dktport"] = node->port;
							ctx->idktport = atoi(node->port.c_str());
							strncpy(ctx->dktip, node->ip.c_str(), IP_ADDRESS_STRING_MAX);
							strncpy(ctx->dktport, node->port.c_str(), PORT_STRING_MAX);
							std::cerr << "detection ip [" << node->ip << "] port [" << node->port << "]\n";
						} else {
							g_nodes.push_back(node);
							std::cerr << "node ip [" << node->ip << "] port [" << node->port << "]\n";
						}
                	}
                */
                } else

                // misc
				if (!key_str.compare("misc")) {
					std::cerr << "misc\n";
	        		CHECK_YAML(value, Map);
	            	for (YAML::Iterator itr(value.begin()), end(value.end()); itr != end; ++itr) {
	                    const YAML::Node &key   = itr.first();
	                    const YAML::Node &value = itr.second();
	            		CHECK_YAML(key, Scalar);
	            		CHECK_YAML(value, Scalar);
						std::string key_str;
						key >> key_str;
						std::string value_str;
						value >> value_str;
						std::cerr << "key [" << key_str << "] value [" << value_str << "]\n";

						// コンテキストに格納
						//std::cerr << "value [" << value_str << "] atoi [" << atoi(value_str.c_str()) << "]\n";
	            		if (!key_str.compare("architecture")) {
	            			ctx->architecture = atoi(value_str.c_str());
	            		} else
						if (!key_str.compare("timeSlotSize")) {
							ctx->timeSlotSize = atoi(value_str.c_str());
						} else
						if (!key_str.compare("localAlertTimeSlotSize")) {
							ctx->localAlertTimeSlotSize = atoi(value_str.c_str());
						} else
						if (!key_str.compare("localAlertThreshold")) {
							ctx->localAlertThreshold = atoi(value_str.c_str());
						} else
						if (!key_str.compare("globalAlertTimeSlotSize")) {
							ctx->globalAlertTimeSlotSize = atoi(value_str.c_str());
						} else
						if (!key_str.compare("globalAlertThreshold")) {
							ctx->globalAlertThreshold = atoi(value_str.c_str());
						} else
						if (!key_str.compare("globalAlertGenerationSlot")) {
							ctx->globalAlertGenerationSlot = atoi(value_str.c_str());
						} else
						if (!key_str.compare("blacklistLastTimeSlotSize")) {
							ctx->blacklistLastTimeSlotSize = atoi(value_str.c_str());
						} else
						if (!key_str.compare("nodelistfile")) {
							getNodeListFile(value_str.c_str(), ctx, conf);
						} else
						if (!key_str.compare("logfile")) {
							openLogFile(value_str.c_str(), ctx, conf);
						} else
						if (!key_str.compare("fakedata")) {
							ctx->fakeData = atoi(value_str.c_str());
						} else
//						if (!key_str.compare("")) {
//							ctx-> = atoi(value_str.c_str());
//						} else

						// unknown
						{
							std::cerr << "unknown key [" << key_str.c_str() << "]\n";
							abort();
						}
	            	}
				} else

                // 特徴リスト
                if (!key_str.compare("features")) {
					std::cerr << "features list\n";
            		CHECK_YAML(value, Sequence);
                    for (unsigned j = 0; j < value.size(); j++) {
	            		CHECK_YAML(value[j], Scalar);
						std::string feature_str;
						value[j] >> feature_str;

						// 特徴リストに格納
						g_features.push_back(feature_str);

						// 参加ドメインリストに格納
						std::string id_str;
						getIDfromStr(feature_str.c_str(), id_str);
						TRACE2("feature [%s] hash [%s]\n", feature_str.c_str(), id_str.c_str());
						g_domainids.push_back(id_str);
                    }
                } else

				// KyotoTycoon引数
				if (!key_str.compare("ktargs")) {
					std::cerr << "ktargs\n";
            		CHECK_YAML(value, Sequence);
					for (unsigned j = 0; j < value.size(); j++) {
	            		CHECK_YAML(value[j], Scalar);
						std::string arg_str;
						value[j] >> arg_str;
						std::cerr << "arg [" << arg_str << "]\n";

						// KyotoTycoonの引数に格納
						g_ktargs.push_back(arg_str);

					}
				} else

                // unknown
                {
					TRACE1("unknown key[%1%]\n", key_str.c_str());
					abort();
                }
    		}
        }

	} catch(YAML::Exception &e) {
		TRACE1("error:%1%\n", e.what());
		abort();
	}

	if (ctx->localAlertTimeSlotSize < 1 ||
		ctx->localAlertThreshold < 0 ||
		ctx->globalAlertTimeSlotSize < 1 ||
		ctx->globalAlertThreshold < 0 ||
		ctx->globalAlertGenerationSlot < 0 ||
		ctx->blacklistLastTimeSlotSize < 0
		) {
		TRACE("conffile incomplete!\n");
		abort();
	}

}

// timestampを編集する
void formatTimeStampCpp(timeval* tv, char *timestamp) {

    time_t Time = tv->tv_sec;
    struct tm *lt = localtime(&Time);
    sprintf(timestamp, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
    		lt->tm_year - 100, lt->tm_mon + 1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec, (u_int) tv->tv_usec);

}

// 文字列(string)を分割してベクトルを作成する
void splitString(std::vector<std::string> &vec, const std::string &str, const char *delimiter) {

	boost::algorithm::split(vec, str, boost::is_any_of(delimiter));

}

// 文字列(const char*)を分割してベクトルを作成する
void splitString(std::vector<std::string> &vec, const char *str, const char *delimiter) {

	std::string str_str(str);
	splitString(vec, str_str, delimiter);

}
