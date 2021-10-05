#ifndef KEX_KYBER_H
#define KEX_KYBER_H

/**
 * @author Simon Burkhardt
 */

#define KEX_FILE_SENDA "./ake_senda.txt"
#define KEX_FILE_SENDB "./ake_sendb.txt"
#define KEX_FILE_SKA "./SKA.key"
#define KEX_FILE_PKA "./PKA.key"
#define KEX_FILE_PKB "./PKB.key"
#define KEX_FILE_ESKA "./eska.key"
#define KEX_FILE_TK "./tk.key"
#define KEX_FILE_COMMON "./COMMON.key"
/*
#define KEX_FILE_SKA "./SKA.key"
#define KEX_FILE_SKB "./SKB.key"
*/

void cmd_kex_kyber_setup(void);

struct command_context {
    char **argv;
    int argc;
    int dummy;
};

/*
int cmd_kex_kyber_init(struct command_context *ctx);
int cmd_kex_kyber_pub(struct command_context *ctx);
int cmd_kex_kyber_initA(struct command_context *ctx);
int cmd_kex_kyber_sharedB(struct command_context *ctx);
int cmd_kex_kyber_sharedA(struct command_context *ctx);
int cmd_kex_kyber_show_pka(struct command_context *ctx);
int cmd_kex_kyber_show_ska(struct command_context *ctx);
int cmd_kex_kyber_show_pkb(struct command_context *ctx);
int cmd_kex_kyber_show_key(struct command_context *ctx);
*/

#endif // KEX_KYBER_H 

