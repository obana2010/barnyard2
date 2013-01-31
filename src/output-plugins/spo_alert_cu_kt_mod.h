/*
 * spo_alert_cu_kt_mod.h
 *
 *  Created on: 2012/11/09
 *      Author: obana
 */

#ifndef SPO_ALERT_CU_KT_MOD_H_
#define SPO_ALERT_CU_KT_MOD_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// **************************************************************************
enum {                                   // enumeration for operation counting
  CNTSET,                                // setting operations
  CNTSETMISS,                            // misses of setting operations
  CNTREMOVE,                             // removing operations
  CNTREMOVEMISS,                         // misses of removing operations
  CNTGET,                                // getting operations
  CNTGETMISS,                            // misses of getting operations
  CNTSCRIPT,                             // scripting operations
  CNTMISC                                // miscellaneous operations
};
typedef uint64_t OpCount[CNTMISC+1];     // counters per thread
typedef kt::RPCClient::ReturnValue RV;

// Workerの追加分の宣言
// 継承できるように作られていないので、直接拡張を行う
class Worker : public kt::RPCServer::Worker {
 private:
  void set_message(std::map<std::string, std::string>& outmap, const char* key,
				   const char* format, ...);
  void set_db_error(std::map<std::string, std::string>& outmap, const kc::BasicDB::Error& e);
  void log_db_error(kt::RPCServer* serv, const kc::BasicDB::Error& e);
  void log_db_error(kt::HTTPServer* serv, const kc::BasicDB::Error& e);

  // ドメイン参加要求
  RV do_join_domain(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap);

  // アラート蓄積
  RV do_store_global_alert(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap);

  // ドメインノードリスト取得
  RV do_get_domain_node_list(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap);

  // BLを受け入れる
  RV do_share_blacklist(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap);

  // ステータスを表示する(テスト用)
  RV do_cu_status(kt::RPCServer* serv, kt::RPCServer::Session* sess,
            const std::map<std::string, std::string>& inmap,
            std::map<std::string, std::string>& outmap);

  int32_t thnum_;
  kc::CondMap* const condmap_;
  kt::TimedDB* const dbs_;
  const int32_t dbnum_;
  const std::map<std::string, int32_t>& dbmap_;
  const int32_t omode_;
  const double asi_;
  const bool ash_;
  const char* const bgspath_;
  const double bgsi_;
  kc::Compressor* const bgscomp_;
  kt::UpdateLogger* const ulog_;
  DBUpdateLogger* const ulogdbs_;
  const char* const cmdpath_;
  ScriptProcessor* const scrprocs_;
  OpCount* const opcounts_;
  uint64_t idlecnt_;
  double asnext_;
  double bgsnext_;
//  Slave* slave_;
};

#endif /* SPO_ALERT_CU_KT_MOD_H_ */
