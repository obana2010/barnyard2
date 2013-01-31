/*
 * spo_alert_cu_util.h
 *
 *  Created on: 2012/11/09
 *      Author: obana
 */

#ifndef SPO_ALERT_CU_UTIL_H_
#define SPO_ALERT_CU_UTIL_H_

// for c++ only

// 文字列からIDを求める
int getIDfromStr(const char *idseed_str, std::string &id_str);
int getIDfromStr(const char *idseed_str, unsigned char *id_str);

// timestampを編集する
void formatTimeStampCpp(timeval* tv, char *timestamp);
void splitString(std::vector<std::string> &vec, const std::string &str, const char *delimiter);
// 文字列のスプリット
void splitString(std::vector<std::string> &vec, const std::string &str, const char *delimiter);
void splitString(std::vector<std::string> &vec, const char *str, const char *delimiter);

// local alert storeのkey生成
void formatLocalAlertStoreKey(
		char *key,
		const char *sourceip,
		unsigned long timeslot,
		const char *timestamp);

// global alert storeのkey生成
void formatGlobalAlertStoreKey(
		std::string &key,
		std::string &value,
		const char *sourceip,
		const char *domainid,
		const char *timeslot,
		const char *count,
		const char *nodeid);

// nodeid生成
#define NODEID_MAX IP_ADDRESS_STRING_MAX+PORT_STRING_MAX
void formatNodeID(char *nodeid, size_t nodeidsize, const char *nodeip, const char *nodeport);

// タイムスタンプを作成する
void formatTimeStampLog(char *timestamp, size_t size);

void writelog(const char *format, char *value1, char *value2, char *value3);
void writelog(const char *format, char *value1, char *value2);
void writelog(const char *format, char *value1);
void writelog(const char *message);

#endif /* SPO_ALERT_CU_UTIL_H_ */
