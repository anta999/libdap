#include <assert.h>
#include <string.h>
#include "tesla_params.h"


static const tesla_param_t tesla_params[] = {

  { qTESLA_I,          /* kind */
    512,
    9,
    23.78,
    27.9988,
    4205569,
    23,
    3098553343,
    1021,
    32,
    1048575,
    20,
    1,
    23.78,
    30,
    21,
    19,
    1586,
    1586,
    1586,
    1586,
    113307,

    1376,//((512*21+7)/8 + 32),
    2112,//2*sizeof(int16_t)*512 + 2*32,
    1504 //((512*23+7)/8 + 32)
  },

  { qTESLA_III_size,   /* kind */
    1024,
    10,
    8.49,
    9.9962,
    4206593,
    23,
    4148178943,
    1021,
    32,
    1048575,
    20,
    1,
    8.49,
    48,
    21,
    38,
    910,
    910,
    910,
    910,
    1217638,

    2720,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    4160,//(2*sizeof(int16_t)*PARAM_N + 2*CRYPTO_SEEDBYTES)
    2976 //((PARAM_N*PARAM_Q_LOG+7)/8 + CRYPTO_SEEDBYTES)
  },

  { qTESLA_III_speed,  /* kind */
    1024,
    10,
    10.2,
    12,
    8404993,
    24,
    4034936831,
    511,
    32,
    2097151,
    21,
    1,
    10.2,
    48,
    22,
    38,
    1147,
    1147,
    1233,
    1233,
    237839,

    2848,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    4160,//(2*sizeof(int16_t)*PARAM_N + 2*CRYPTO_SEEDBYTES)
    3104 //((PARAM_N*PARAM_Q_LOG+7)/8 + CRYPTO_SEEDBYTES)
  },

  { qTESLA_p_I,        /* kind */
    1024,
    10,
    8.5,
    10,
    485978113,
    29,
    3421990911,
    1,
    29,
    2097151,
    21,
    4,
    8.5,
    25,
    22,
    108,
    554,
    554,
    554,
    554,
    472064468,

    2848,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    5184,//(sizeof(int8_t)*PARAM_N + sizeof(int8_t)*PARAM_N*PARAM_K + 2*CRYPTO_SEEDBYTES)
    14880 //((PARAM_Q_LOG*PARAM_N*PARAM_K+7)/8 + CRYPTO_SEEDBYTES)
  },

  { qTESLA_p_III,      /* kind */
    2048,
    11,
    8.5,
    10,
    1129725953,
    31,
    861290495,
    15,
    34,
    8388607,
    23,
    5,
    8.5,
    40,
    24,
    180,
    901,
    901,
    901,
    901,
    851423148,

    6176,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    12352,//(sizeof(int8_t)*PARAM_N + sizeof(int8_t)*PARAM_N*PARAM_K + 2*CRYPTO_SEEDBYTES)
    39712 //((PARAM_Q_LOG*PARAM_N*PARAM_K+7)/8 + CRYPTO_SEEDBYTES)
  },
};

bool tesla_params_init(tesla_param_t *params, tesla_kind_t kind){
  assert(params != NULL);

  memset(params, 0, sizeof(tesla_param_t));
  
  if (qTESLA_I <= kind && kind <= qTESLA_p_III  && params != NULL) {
    *params = tesla_params[kind];
    return true;
  } else {
    return false;
  }
}

#include "dap_common.h"

/* Serialize a private key. */
uint8_t* tesla_write_private_key(const tesla_private_key_t* a_private_key, size_t *a_buflen_out)
{
    tesla_param_t p;// = malloc(sizeof(tesla_param_t));
    if(!tesla_params_init(&p, a_private_key->kind))
        return NULL;

    size_t l_buflen = sizeof(size_t) + sizeof(tesla_kind_t) + p.CRYPTO_SECRETKEYBYTES; //CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_private_key->kind, sizeof(tesla_kind_t));
    memcpy(l_buf + sizeof(size_t) + sizeof(tesla_kind_t), a_private_key->data, p.CRYPTO_SECRETKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    return l_buf;
}

/* Serialize a public key. */
uint8_t* tesla_write_public_key(const tesla_public_key_t* a_public_key, size_t *a_buflen_out)
{
    tesla_param_t p;
    if(!tesla_params_init(&p, a_public_key->kind))
        return NULL;

    size_t l_buflen = sizeof(size_t) + sizeof(tesla_kind_t) + p.CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_public_key->kind, sizeof(tesla_kind_t));
    memcpy(l_buf + sizeof(size_t) + sizeof(tesla_kind_t), a_public_key->data, p.CRYPTO_PUBLICKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    return l_buf;
}

/* Deserialize a private key. */
tesla_private_key_t* tesla_read_private_key(uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(tesla_kind_t)))
        return NULL;
    tesla_kind_t kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(tesla_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    tesla_param_t p;
    if(!tesla_params_init(&p, kind))
        return NULL;
    tesla_private_key_t* l_private_key = DAP_NEW(tesla_private_key_t);
    l_private_key->kind = kind;

    l_private_key->data = DAP_NEW_SIZE(unsigned char, p.CRYPTO_SECRETKEYBYTES);
    memcpy(l_private_key->data, a_buf + sizeof(size_t) + sizeof(tesla_kind_t), p.CRYPTO_SECRETKEYBYTES);
    return l_private_key;
}

/* Deserialize a public key. */
tesla_public_key_t* tesla_read_public_key(uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(tesla_kind_t)))
        return NULL;
    tesla_kind_t kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(tesla_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    tesla_param_t p;
    if(!tesla_params_init(&p, kind))
        return NULL;
    tesla_public_key_t* l_public_key = DAP_NEW(tesla_public_key_t);
    l_public_key->kind = kind;

    l_public_key->data = DAP_NEW_SIZE(unsigned char, p.CRYPTO_PUBLICKEYBYTES);
    memcpy(l_public_key->data, a_buf + sizeof(size_t) + sizeof(tesla_kind_t), p.CRYPTO_PUBLICKEYBYTES);
    return l_public_key;
}
