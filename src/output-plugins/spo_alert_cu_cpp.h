#ifndef __SPO_ALERT_CU_CPP_H__
#define __SPO_ALERT_CU_CPP_H__

// C++ headers
#include <vector>
#include <iostream>
#include <fstream>
#include <yaml-cpp/yaml.h>

// Boost headers
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>

// local store configuration
#define LOCALSTORE_MAXKEYSIZE 100
#define LOCALSTORE_KEYDELIMITER "&"
// global store configuration
#define GLOBALSTORE_KEY_MAXSIZE 100
#define GLOBALSTORE_KEY_DELIMITER "&"
#define GLOBALSTORE_VALUE_MAXSIZE 100

#define GLOBALSTORE_DOMAINS_DELIMITER "&"

struct ConfCpp {
	std::ofstream *logfs;
};

// ノード構造体
struct CIDNNode {
   std::string name;
   std::string ip;
   std::string port;
};

// YAML型チェック
#define CHECK_YAML(x,y) (YAML::NodeType::y != x.Type()) && std::cerr << "Invalied type! line " << __LINE__ << "\n";
// 変数ダンプ
#define HEXDUMPFP(hexdump_fp, hexdump_name, hexdump_data, hexdump_size) fprintf(hexdump_fp, "HEX(" #hexdump_name ") ["); \
for (int hexdump_i = 0; hexdump_i < hexdump_size; hexdump_i++){ \
	fprintf(hexdump_fp, "%02X", *(hexdump_data + hexdump_i)); \
} \
fprintf(hexdump_fp, "]\n");

#define HEXDUMPCHAR(hexdump_char, hexdump_data, hexdump_size) \
for (int hexdump_i = 0; hexdump_i < hexdump_size; hexdump_i++){ \
	sprintf(hexdump_char + (hexdump_i * 2), "%02X", *(hexdump_data + hexdump_i)); \
}

// トレースログ出力
#define TRACE(f) std::cout << boost::format(f) << std::endl;
#define TRACE0(f) std::cout << boost::format(f) << std::endl;
#define TRACE1(f, a) std::cout << boost::format(f) % a << std::endl;
#define TRACE2(f, a, b) std::cout << boost::format(f) % a % b << std::endl;
#define TRACE3(f, a, b, c) std::cout << boost::format(f) % a % b % c << std::endl;
#define TRACE4(f, a, b, c, d) std::cout << boost::format(f) % a % b % c % d << std::endl;
#define TRACE5(f, a, b, c, d, e) std::cout << boost::format(f) % a % b % c % d % e << std::endl;

// トレースログ出力 ポート番号を含める
extern SpoAlertCuData *g_ctx;
#if 0
#define TRACEP(f) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) << std::endl;
#define TRACEP0(f) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) << std::endl;
#define TRACEP1(f, a) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) % a << std::endl;
#define TRACEP2(f, a, b) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) % a % b << std::endl;
#define TRACEP3(f, a, b, c) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) % a % b % c << std::endl;
#define TRACEP4(f, a, b, c, d) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) % a % b % c % d << std::endl;
#define TRACEP5(f, a, b, c, d, e) std::cout << "[" << g_ctx->cktport << "]" << boost::format(f) % a % b % c % d % e << std::endl;
#endif

#define TRACEP(f) \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
			std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) << std::endl; \
		}
#define TRACEP0(f) \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
			std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) << std::endl; \
		}
#define TRACEP1(f, a)  \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
			std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) % a << std::endl; \
		}
#define TRACEP2(f, a, b)  \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
			std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) % a % b << std::endl; \
		}
#define TRACEP3(f, a, b, c)  \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
			std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) % a % b % c << std::endl; \
		}
#define TRACEP4(f, a, b, c, d)  \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
			std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) % a % b % c % d << std::endl; \
		}
#define TRACEP5(f, a, b, c, d, e)  \
		1; { \
			char timestamp[100]; \
			formatTimeStampLog(timestamp, sizeof(timestamp)); \
		std::cout << timestamp << " [" << g_ctx->cktport << "]" << " [" << g_ctx->current_timeslot << "]" << boost::format(f) % a % b % c % d % e << std::endl; \
		}


// function prototypes
// mod main
int ktmain(int argc, char** argv);

// グローバルの宣言
extern std::vector<CIDNNode *> g_nodes;
extern std::vector<std::string> g_features;
extern std::vector<std::string> g_domainids;
extern std::vector<std::string> g_ktargs;

#endif  /* __SPO_ALERT_CU_CPP_H__ */

