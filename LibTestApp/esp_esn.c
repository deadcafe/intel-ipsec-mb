#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "gcm_ctr_vectors_test.h"
#include "mb_mgr.h"

typedef UINT32 BE32;
typedef UINT64 BE64;

struct packet_s {
        uint8_t reserved[8];
        struct {
                BE32 spi;
                BE32 seq32_lo;
        };
        UINT8 iv[16];
        UINT8 payload[16];
        union {
                UINT8 tag[12];
                BE32 seq32_hi;
        };
        uint8_t pad[4];
} __attribute__((packed));

struct ipsec_sa_s {
        UINT8 enc_key[16 * 16];
        UINT8 dec_key[16 * 16];
        UINT8 ipad[64];
        UINT8 opad[64];

        union {
                UINT64 seq64;
                struct {
                        UINT32 seq32_lo;
                        UINT32 seq32_hi;
                };
        };
        UINT32 spi;
        bool isBusy;
};

static int Errors;

#define SWAP(a,b)	do { typeof(a) c = (a); a = (b); (b) = c; } while (0)

static inline BE32
hton32(uint32_t n)
{
        union {
                uint32_t raw;
                uint8_t byte[4];
        } u;

        u.raw = n;
        SWAP(u.byte[0], u.byte[3]);
        SWAP(u.byte[1], u.byte[2]);
        return u.raw;
}

enum job_ret_e {
        OTHER_ERROR = -1,
        JOB_SUCCESS = 0,
        AUTH_FAILED = 1,
};

static enum job_ret_e chk_result(MB_MGR *mgr, JOB_AES_HMAC *job);

static enum job_ret_e
dec_packet(MB_MGR *mgr,
           struct ipsec_sa_s *sa,
           struct packet_s *pkt)
{
        enum job_ret_e ret = JOB_SUCCESS;
        JOB_AES_HMAC *job;

        while ((job = IMB_GET_NEXT_JOB(mgr)) == NULL) {
                ret = chk_result(mgr, IMB_FLUSH_JOB(mgr));
                if (!ret)
                        goto end;
        }

        job->aes_enc_key_expanded = sa->enc_key;
        job->aes_dec_key_expanded = sa->dec_key;
        job->aes_key_len_in_bytes = 16;
        job->src = (const UINT8 *) pkt;
        job->dst = pkt->payload;
        job->cipher_start_src_offset_in_bytes =
                offsetof(struct packet_s, payload);
        job->msg_len_to_cipher_in_bytes = sizeof(pkt->payload);
        job->hash_start_src_offset_in_bytes = offsetof(struct packet_s, spi);
        job->msg_len_to_hash_in_bytes = 8 + 16 + 16 + 4;
        job->iv = pkt->iv;
        job->iv_len_in_bytes = 16;
        job->auth_tag_output = pkt->tag;
        job->auth_tag_output_len_in_bytes = 12;
        job->u.HMAC._hashed_auth_key_xor_ipad = sa->ipad;
        job->u.HMAC._hashed_auth_key_xor_opad = sa->opad;
        job->cipher_mode = CBC;
        job->cipher_direction = DECRYPT;
        job->hash_alg = SHA1;
        job->chain_order = HASH_CIPHER;
        job->user_data  = sa;
        job->user_data2 = pkt;

        /* save TAG */
        memcpy(job->cmp_tag, pkt->tag, job->auth_tag_output_len_in_bytes);

        /* overwrap seq32_hi */
        pkt->seq32_hi = hton32(sa->seq32_hi);
        sa->isBusy = true;

        job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        while (job) {
                if ((ret = chk_result(mgr, job)) != JOB_SUCCESS)
                        break;
                job = IMB_GET_COMPLETED_JOB(mgr);
        }
 end:
        return ret;
}

static enum job_ret_e
chk_result(MB_MGR *mgr,
           JOB_AES_HMAC *job)
{
        struct ipsec_sa_s *sa = job->user_data;
        struct packet_s *pkt = job->user_data2;

        sa->isBusy = false;
        switch (job->status) {
        case STS_COMPLETED:
                if (job->cipher_direction == DECRYPT) {
                        if (memcmp(job->auth_tag_output,
                                   job->cmp_tag,
                                   job->auth_tag_output_len_in_bytes)) {
                                fprintf(stderr, "mismatched spi:%u lo:%u hi:%u\n",
                                        sa->spi, sa->seq32_lo, sa->seq32_hi);
                                return AUTH_FAILED;
                        } else {
#if 1
                                fprintf(stderr, "ok spi:%u lo:%u hi:%u\n",
                                        sa->spi, sa->seq32_lo, sa->seq32_hi);
#endif
                                sa->seq64 += UINT64_C(1);
                        }
                } else {
                        return dec_packet(mgr, sa, pkt);
                }
                break;

        case STS_INVALID_ARGS:
        case STS_INTERNAL_ERROR:
        case STS_ERROR:
        default:
                return OTHER_ERROR;
        }
        return JOB_SUCCESS;
}

static enum job_ret_e
enc_packet(MB_MGR *mgr,
           struct ipsec_sa_s *sa,
           struct packet_s *pkt)
{
        enum job_ret_e ret = JOB_SUCCESS;
        JOB_AES_HMAC *job;

        pkt->seq32_lo = hton32(sa->seq32_lo);
        pkt->seq32_hi = hton32(sa->seq32_hi);
        sa->isBusy = true;
        while ((job = IMB_GET_NEXT_JOB(mgr)) == NULL) {
                ret = chk_result(mgr, IMB_FLUSH_JOB(mgr));
                if (ret != JOB_SUCCESS)
                        goto end;
        }

        job->aes_enc_key_expanded = sa->enc_key;
        job->aes_dec_key_expanded = sa->dec_key;
        job->aes_key_len_in_bytes = 16;
        job->src = (const UINT8 *) pkt;
        job->dst = pkt->payload;
        job->cipher_start_src_offset_in_bytes =
                offsetof(struct packet_s, payload);
        job->msg_len_to_cipher_in_bytes = sizeof(pkt->payload);
        job->hash_start_src_offset_in_bytes =
                offsetof(struct packet_s, spi);
        job->msg_len_to_hash_in_bytes = 8 + 16 + 16 + 4;
        job->iv = pkt->iv;
        job->iv_len_in_bytes = 16;
        job->auth_tag_output = pkt->tag;
        job->auth_tag_output_len_in_bytes = 12;
        job->u.HMAC._hashed_auth_key_xor_ipad = sa->ipad;
        job->u.HMAC._hashed_auth_key_xor_opad = sa->opad;
        job->cipher_mode = CBC;
        job->cipher_direction = ENCRYPT;
        job->hash_alg = SHA1;
        job->chain_order = CIPHER_HASH;
        job->user_data  = sa;
        job->user_data2 = pkt;

        job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        while (job) {
                if ((ret = chk_result(mgr, job)) != JOB_SUCCESS)
                        break;
                job = IMB_GET_COMPLETED_JOB(mgr);
        }
 end:
        return ret;
}


#define SA_NUM	128

int
test_esp_esn(MB_MGR *mgr)
{
        DECLARE_ALIGNED(struct ipsec_sa_s ipsec_sa[SA_NUM], 16);
        DECLARE_ALIGNED(struct packet_s packets[SA_NUM], 16);
        UINT8 cipher_key[16];
        enum job_ret_e ret = JOB_SUCCESS;

        for (unsigned i = 0; i < SA_NUM; i++) {
                ipsec_sa[i].seq64 = UINT64_C(0xfffffff0) + i;
                ipsec_sa[i].spi = i + 1;
                ipsec_sa[i].isBusy = false;

                packets[i].spi      = hton32(ipsec_sa[i].spi);
                packets[i].seq32_lo = hton32(ipsec_sa[i].seq32_lo);

                IMB_AES_KEYEXP_128(mgr, cipher_key,
                                   ipsec_sa[i].enc_key,
                                   ipsec_sa[i].dec_key);
        }

        while (!ipsec_sa[0].seq32_hi) {
                for (unsigned i = 0; i < SA_NUM; i++) {
                        while (ipsec_sa[i].isBusy) {
                                ret = chk_result(mgr, IMB_FLUSH_JOB(mgr));
                                if (ret != JOB_SUCCESS)
                                        goto end;
                        }

                        ret = enc_packet(mgr, &ipsec_sa[i], &packets[i]);
                        if (ret != JOB_SUCCESS)
                                goto end;
                }
        }

 end:
        if (ret != JOB_SUCCESS)
                fprintf(stderr, "failed ESP esn test\n");

        while (IMB_FLUSH_JOB(mgr) != NULL)
                /* clear */;
        return ret;
}

