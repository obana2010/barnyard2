/*
** Copyright (C) 2012 NAIST
**
** spo_alert_testを基に作成している
**
*/

/* output plugin header file */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "barnyard2.h"
#include "decode.h"
#include "debug.h"
#include "log.h"
#include "map.h"
#include "mstring.h"
#include "parser.h"
#include "plugbase.h"
#include "unified2.h"
#include "util.h"

#include "spo_alert_cu.h"

#define TEST_FLAG_FILE     0x01
#define TEST_FLAG_STDOUT   0x02
#define TEST_FLAG_MSG      0x04
#define TEST_FLAG_SESSION  0x08
#define TEST_FLAG_REBUILT  0x10

void AlertCuInit(char *);
SpoAlertCuData *ParseAlertCuArgs(char *);
void AlertCuCleanExitFunc(int, void *);
void AlertCuRestartFunc(int, void *);
void AlertCu(Packet *, void *, uint32_t, void *);

/*
 * Function: AlertCuSetup()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AlertCuSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_cu", OUTPUT_TYPE_FLAG__ALERT, AlertCuInit);
//    RegisterOutputPlugin("alert_cu", OUTPUT_TYPE_FLAG__ALL, AlertCuInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"**** Output plugin: AlertCu is setup...\n"););

}

/*
 * Function: AlertCuInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertCuInit(char *args)
{
    SpoAlertCuData *ctx;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: AlertCu Initialized\n"););

    /* parse the argument list from the rules file */
    ctx = ParseAlertCuArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking AlertCu functions to call lists...\n"););
    
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertCu, OUTPUT_TYPE__ALERT, ctx);
    AddFuncToCleanExitList(AlertCuCleanExitFunc, ctx);
    AddFuncToRestartList(AlertCuRestartFunc, ctx);

    /* CPPで初期化する */
    AlertCuInitCpp(ctx);

}

/* アラートを処理する */
void AlertCu(Packet *p, void *event, u_int32_t event_type, void *arg)
{

	/* コンテキスト取得 */
	SpoAlertCuData *ctx = (SpoAlertCuData *)arg;
	/* イベント取得 */
	Unified2EventCommon *u_event = (Unified2EventCommon *)event;

	fprintf(ctx->file, "**** processing AlertCu() ****\n");

    if (event == NULL || arg == NULL) {
    	fprintf(ctx->file, "**** event is NULL! exit ****\n");
        return;
    }

    fprintf(ctx->file, "gid[%lu]\tsig[%lu]\trev[%lu]\t",
            (unsigned long) ntohl((u_event)->generator_id),
            (unsigned long) ntohl((u_event)->signature_id),
            (unsigned long) ntohl((u_event)->signature_revision));

    /* シグニチャを取得 */
	SigNode *sn = GetSigByGidSid(ntohl((u_event)->generator_id), ntohl((u_event)->signature_id));
	if(sn)
		fprintf(ctx->file, "%s\n", sn->msg);

	/* パケットが有効な場合 */
	if (p && IPH_IS_VALID(p)) {

		/* CPP構造体に詰め替える(ディープコピーはしない) */
		PacketCpp pcpp;
		memset(&pcpp, 0x00, sizeof(pcpp));
		pcpp.pkth = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
		pcpp.sp = p->sp;
		pcpp.dp = p->dp;
		if (p->pkth){
			pcpp.pkth->caplen = p->pkth->caplen;
			pcpp.pkth->len = p->pkth->len;
			pcpp.pkth->ts = p->pkth->ts;
		} else {
			fprintf(ctx->file, "p->okth is NULL\n");
		}

		/* CPPのルーチンを呼び出す */
		char ip_src[30], ip_dst[30];
		strncpy(ip_src, inet_ntoa(GET_SRC_ADDR(p)), sizeof(ip_src));
		strncpy(ip_dst, inet_ntoa(GET_DST_ADDR(p)), sizeof(ip_dst));
		AlertCuProcess(&pcpp, event, ip_src, p->sp, ip_dst, p->dp, ctx);

		free(pcpp.pkth);
	} else {
		fprintf(ctx->file, "**** no ip header ****\n");
	}

    if (ctx->flags & TEST_FLAG_SESSION)
    {
        if (IPH_IS_VALID(p))
        {
            fprintf(ctx->file, "test %s:%d", inet_ntoa(GET_SRC_ADDR(p)), p->sp);
            fprintf(ctx->file, "-%s:%d\t", inet_ntoa(GET_DST_ADDR(p)), p->dp);
        }
    }

/*
    if (data->flags & TEST_FLAG_REBUILT)
    {
        if (p->packet_flags & PKT_REBUILT_FRAG)
        {
            fprintf(data->file, "F:" STDu64 "\t", pc.rebuilt_frags);
        }
        else if (p->packet_flags & PKT_REBUILT_STREAM)
        {
            fprintf(data->file, "S:" STDu64 "\t", pc.rebuilt_tcp);
        }
    }
*/
    fprintf(ctx->file, "\n");
    fflush(ctx->file);

    return;
}

/*
 * Function: ParseAlertTestArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
SpoAlertCuData *ParseAlertCuArgs(char *args)
{
    char **toks;
    char *option;
    int num_toks;
    SpoAlertCuData *data;
    int i;

    data = (SpoAlertCuData *)SnortAlloc(sizeof(SpoAlertCuData));

    /* KyotoTycoon待受ポートのデフォルト YAMLから設定する */
    strncpy(data->cktport, KYOTOTYCOON_DEFAULT_PORT, sizeof(data->cktport));

    /* バッチ・モードかどうか */
    data->isBatchMode = (barnyard2_conf->run_mode == RUN_MODE__BATCH)? 1: 0;

    if(args == NULL)
    {
        data->file = OpenAlertFile(NULL);
        data->flags |= TEST_FLAG_FILE;
        return data;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "ParseAlertCuArgs: %s\n", args););

    toks = mSplit(args, ",", 5, &num_toks, 0);

    for (i = 0; i < num_toks; i++)
    {
        option = toks[i];

        while (isspace((int)*option))
            option++;

        if(strncasecmp("stdout", option, strlen("stdout")) == 0)
        {
            if (data->flags & TEST_FLAG_FILE)
            {
                FatalError("alert_test: cannot specify both stdout and file\n");
            }

            data->file = stdout;
            data->flags |= TEST_FLAG_STDOUT;
        }
        else if (strncasecmp("session", option, strlen("session")) == 0)
        {
            data->flags |= TEST_FLAG_SESSION;
        }
        else if (strncasecmp("rebuilt", option, strlen("rebuilt")) == 0)
        {
            data->flags |= TEST_FLAG_REBUILT;
        }
        else if (strncasecmp("msg", option, strlen("msg")) == 0)
        {
            data->flags |= TEST_FLAG_MSG;
        }
        else if (strncasecmp("file", option, strlen("file")) == 0)
        {
            char *filename;

            if (data->flags & TEST_FLAG_STDOUT)
            {
                FatalError("alert_test: cannot specify both stdout and file\n");
            }
                
            filename = strstr(option, " ");

            if (filename == NULL)
            {
                data->file = OpenAlertFile(NULL);
                data->flags |= TEST_FLAG_FILE;
            }
            else
            {
                while (isspace((int)*filename))
                    filename++;

                if (*filename == '\0')
                {
                    data->file = OpenAlertFile(NULL);
                    data->flags |= TEST_FLAG_FILE;
                }
                else
                {
                    char *filename_end;
                    char *outfile;

                    filename_end = filename + strlen(filename) - 1;
                    while (isspace((int)*filename_end))
                        filename_end--;

                    filename_end++;
                    filename_end = '\0';

                    outfile = ProcessFileOption(barnyard2_conf_for_parsing, filename);
                    data->file = OpenAlertFile(outfile);
                    data->flags |= TEST_FLAG_FILE;
                    free(outfile);
                }
            }
        }
        /* add KyotoTycoonポート YAMLから設定に変更済み */
        else if (strncasecmp(CONF_KTPORT, option, strlen(CONF_KTPORT)) == 0)
        {
            char *port_str;
            port_str = strstr(option, " ");

            if (port_str != NULL) {
            	/* ポート番号の前スペースを飛ばす */
                while (isspace((int)*port_str))
                    port_str++;
                if (*port_str != '\0') {
                	/* ポート番号の後スペースを飛ばす */
                    char *port_str_end;
                    port_str_end = port_str + strlen(port_str) - 1;
                    while (isspace((int)*port_str_end))
                    	port_str_end--;

                    port_str_end++;
                    port_str_end = '\0';

                    /* ポートとして正しい場合のみ設定する */
                    int ktport = atoi(port_str);
                    if (ktport && (1024 < ktport) && (ktport < 65535)) {
                    	strncpy(data->cktport, port_str, sizeof(data->cktport));
                    }
                }
            }
        }
        /* add YAML設定ファイル */
        else if (strncasecmp(CONF_YAMLCONFFILE, option, strlen(CONF_YAMLCONFFILE)) == 0)
        {
            char *filename;
            filename = strstr(option, " ");
            if (filename != NULL) {
                while (isspace((int)*filename))
                    filename++;

                if (*filename != '\0') {
                    char *filename_end;
                    char *conffile;

                    filename_end = filename + strlen(filename) - 1;
                    while (isspace((int)*filename_end))
                        filename_end--;

                    filename_end++;
                    filename_end = '\0';

                    conffile = ProcessFileOption(barnyard2_conf_for_parsing, filename);
                    getConfFile(conffile, data);
                    free(conffile);
                }
            }
        }
        else
        {
            FatalError("Unrecognized alert_cu option: %s\n", option);
        }
    }

    /* free toks */
    mSplitFree(&toks, num_toks);

    /* didn't get stdout or a file to log to */
    if (!(data->flags & (TEST_FLAG_STDOUT | TEST_FLAG_FILE)))
    {
        data->file = OpenAlertFile(NULL);
        data->flags |= TEST_FLAG_FILE;
    }

    return data;
}

/* 終了処理 */
void AlertCuCleanExitFunc(int signal, void *arg)
{
    SpoAlertCuData *ctx = (SpoAlertCuData *)arg;

    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertCuCleanExitFunc\n"););

    /* CPPの終了処理を呼び出す */
    AlertCuCleanExitFuncCpp(signal, ctx);

    fclose(ctx->file);
    free(ctx);

}

void AlertCuRestartFunc(int signal, void *arg)
{
    SpoAlertCuData *ctx = (SpoAlertCuData *)arg;

    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertCuRestartFunc\n"););
    fclose(ctx->file);

    /*free memory from SpoAlertTestData */
    free(ctx);
}

