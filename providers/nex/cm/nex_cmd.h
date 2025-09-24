#ifndef NEX_CMD_H
#define NEX_CMD_H

#define NEX_CMD_REGISTER 1
#define NEX_CMD_CONNECT  2

struct nex_cmd_header {
    uint32_t type;
    uint32_t length;
};

struct nex_cmd_register {
    uint32_t job_id;
    uint32_t tcp_port;
};

struct nex_cmd_connect {
    uint32_t job_id;
};

struct nex_cmd_reply {
    uint32_t status; /* 0 success, errno otherwise */
    uint32_t tcp_port;
};

#endif /* NEX_CMD_H */
