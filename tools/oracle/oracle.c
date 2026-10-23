/*
 * Upstream differential oracle for the Rust port.
 *
 * Compiles the upstream C sources of UxPlay (lib/srp.c, lib/crypto.c,
 * lib/pairing.c, lib/fairplay_playfair.c, lib/playfair/*) into one small test
 * program. It never links into the product; it exists so that claims like "the
 * client signature uses the second half of the keystream" or "the server public
 * value is hashed without padding" are checked against the C implementation
 * instead of against a second reading of it.
 *
 * Modes:
 *   crypto                          pair-verify keystream, pair-setup GCM nonces
 *   fairplay                        PlayFair setup/handshake/decrypt vectors
 *   mirror                          the mirror stream's keys and its CTR rule
 *   srp-init [plain|short]          salt, verifier, server public value
 *   srp-verify <salt> <verifier> <b> <A> <M>
 *                                   whether upstream's verifier accepts our
 *                                   client public value and proof, and what it
 *                                   derives from them (all arguments are hex)
 *
 * Build: tools/oracle/build.ps1
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "crypto.h"
#include "fairplay.h"
#include "logger.h"
#include "mirror_buffer.h"
#include "srp.h"

/* The names upstream uses for the one hash and group it supports; `pairing.h`
 * defines them for its own translation unit. */
#ifndef SRP_SHA
#define SRP_SHA SRP_SHA1
#endif
#ifndef SRP_NG
#define SRP_NG SRP_NG_2048
#endif

#define SRP_SALT_SIZE 16
#define SRP_HASH_SIZE 20
#define SESSION_KEY_SIZE 40
#define SIG_SIZE 64
#define GCM_TAG_SIZE 16

static logger_t *logger;

static void emit(const char *key, const unsigned char *data, int length) {
    printf("%s = ", key);
    for (int index = 0; index < length; index++) {
        printf("%02x", data[index]);
        fflush(stdout);
    }
    printf("\n");
}

static void emit_int(const char *key, int value) { printf("%s = %d\n", key, value); }

static void sequence(unsigned char *out, int length) {
    for (int index = 0; index < length; index++) {
        out[index] = (unsigned char)index;
    }
}

static void sha512_labelled(const char *label, const unsigned char *secret, int secret_length,
                            unsigned char out[64]) {
    sha_ctx_t *ctx = sha_init();
    sha_update(ctx, (const uint8_t *)label, (int)strlen(label));
    sha_update(ctx, secret, secret_length);
    sha_final(ctx, out, NULL);
    sha_destroy(ctx);
}

static int hex_value(char digit) {
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
    return -1;
}

/* Parses a hex argument into `out`, which must hold `capacity` bytes. */
static int parse_hex(const char *text, unsigned char *out, int capacity, int *length) {
    int written = 0;
    for (const char *cursor = text; cursor[0] != '\0' && cursor[1] != '\0'; cursor += 2) {
        int high = hex_value(cursor[0]);
        int low = hex_value(cursor[1]);
        if (high < 0 || low < 0 || written >= capacity) {
            return -1;
        }
        out[written++] = (unsigned char)((high << 4) | low);
    }
    *length = written;
    return 0;
}

/* ------------------------------------------------------------------ SRP --- */

static const char *srp_username = "AA:BB:CC:DD:EE:FF";
static const char *srp_password = "1234";

static void srp_init(int short_value) {
    const unsigned char *salt = NULL;
    int salt_length = 0;
    const unsigned char *verifier = NULL;
    int verifier_length = 0;
    srp_create_salted_verification_key(SRP_SHA, SRP_NG, srp_username,
                                      (const unsigned char *)srp_password,
                                      (int)strlen(srp_password), &salt, &salt_length, &verifier,
                                      &verifier_length, NULL, NULL);
    if (salt == NULL || verifier == NULL) {
        printf("srp.error = no verifier\n");
        return;
    }
    emit("srp.salt", salt, salt_length);
    emit("srp.verifier", verifier, verifier_length);

    unsigned char private_b[32];
    for (int index = 0; index < 32; index++) {
        private_b[index] = 0x02;
    }
    const unsigned char *B = NULL;
    int B_length = 0;
    if (short_value) {
        /* Find a private value whose server public value is 255 bytes, that is
         * one with a leading zero byte: the case where "minimal encoding" and
         * "left padded to the modulus size" disagree. */
        for (unsigned int attempt = 0; attempt < 65536; attempt++) {
            unsigned char candidate[32];
            for (int index = 0; index < 32; index++) {
                candidate[index] = 0x10;
            }
            candidate[0] = (unsigned char)(attempt >> 8);
            candidate[1] = (unsigned char)attempt;
            srp_create_server_ephemeral_key(SRP_SHA, SRP_NG, verifier, verifier_length, candidate,
                                           (int)sizeof(candidate), &B, &B_length, NULL, NULL, 1);
            if (B != NULL && B_length == 255) {
                memcpy(private_b, candidate, sizeof(private_b));
                break;
            }
            if (B != NULL) {
                free((void *)B);
                B = NULL;
            }
        }
        if (B == NULL || B_length != 255) {
            printf("srp.error = no 255 byte public value found\n");
            return;
        }
    } else {
        srp_create_server_ephemeral_key(SRP_SHA, SRP_NG, verifier, verifier_length, private_b,
                                       (int)sizeof(private_b), &B, &B_length, NULL, NULL, 1);
    }
    emit("srp.private_b", private_b, sizeof(private_b));
    emit("srp.server_public", B, B_length);
    emit_int("srp.server_public_length", B_length);
}

static void srp_verify(int argc, char **argv) {
    if (argc < 7) {
        printf("srp.error = srp-verify needs salt, verifier, b, A and M\n");
        return;
    }
    unsigned char salt[SRP_SALT_SIZE];
    unsigned char verifier[1024];
    unsigned char private_b[64];
    unsigned char client_public[1024];
    unsigned char proof[SRP_HASH_SIZE];
    int salt_length = 0;
    int verifier_length = 0;
    int private_b_length = 0;
    int client_public_length = 0;
    int proof_length = 0;
    if (parse_hex(argv[2], salt, sizeof(salt), &salt_length) < 0 ||
        parse_hex(argv[3], verifier, sizeof(verifier), &verifier_length) < 0 ||
        parse_hex(argv[4], private_b, sizeof(private_b), &private_b_length) < 0 ||
        parse_hex(argv[5], client_public, sizeof(client_public), &client_public_length) < 0 ||
        parse_hex(argv[6], proof, sizeof(proof), &proof_length) < 0) {
        printf("srp.error = malformed hex argument\n");
        return;
    }
    if (proof_length != SRP_HASH_SIZE) {
        printf("srp.error = the proof has to be %d bytes\n", SRP_HASH_SIZE);
        return;
    }
    printf("# lengths: salt %d, verifier %d, b %d, A %d, M %d\n", salt_length, verifier_length,
           private_b_length, client_public_length, proof_length);
    fflush(stdout);
    /* The constructor writes its own server public value through these two, so
     * they cannot be NULL: upstream dereferences them unconditionally. */
    const unsigned char *B = NULL;
    int B_length = 0;
    struct SRPVerifier *state =
        srp_verifier_new(SRP_SHA, SRP_NG, srp_username, salt, salt_length, verifier,
                         verifier_length, client_public, client_public_length, private_b,
                         private_b_length, &B, &B_length, NULL, NULL, 1);
    if (state == NULL) {
        printf("srp.error = no verifier\n");
        return;
    }
    if (B != NULL) {
        emit("srp.verifier_public", B, B_length);
    }
    printf("# verifier created\n");
    fflush(stdout);
    const unsigned char *M2 = NULL;
    srp_verifier_verify_session(state, proof, &M2);
    printf("# session verified\n");
    fflush(stdout);
    emit_int("srp.authenticated", srp_verifier_is_authenticated(state));
    if (M2 != NULL) {
        emit("srp.server_proof", M2, SRP_HASH_SIZE);
    }
    int session_key_length = 0;
    const unsigned char *session_key = srp_verifier_get_session_key(state, &session_key_length);
    if (session_key != NULL) {
        emit("srp.session_key", session_key, session_key_length);
    }
    srp_verifier_delete(state);
}

/* --------------------------------------------------------- pair-verify --- */

static void crypto_vectors(void) {
    unsigned char shared[32];
    sequence(shared, sizeof(shared));

    unsigned char key_hash[64];
    unsigned char iv_hash[64];
    sha512_labelled("Pair-Verify-AES-Key", shared, sizeof(shared), key_hash);
    sha512_labelled("Pair-Verify-AES-IV", shared, sizeof(shared), iv_hash);
    emit("verify.shared", shared, sizeof(shared));
    emit("verify.key", key_hash, 16);
    emit("verify.iv", iv_hash, 16);

    aes_ctx_t *cipher = aes_ctr_init(key_hash, iv_hash);
    unsigned char keystream[128];
    memset(keystream, 0, sizeof(keystream));
    aes_ctr_encrypt(cipher, keystream, keystream, sizeof(keystream));
    aes_ctr_destroy(cipher);
    emit("verify.keystream0", keystream, SIG_SIZE);
    emit("verify.keystream1", keystream + SIG_SIZE, SIG_SIZE);

    unsigned char session_key[SESSION_KEY_SIZE];
    sequence(session_key, sizeof(session_key));
    emit("setup.session_key", session_key, sizeof(session_key));
    sha512_labelled("Pair-Setup-AES-Key", session_key, sizeof(session_key), key_hash);
    sha512_labelled("Pair-Setup-AES-IV", session_key, sizeof(session_key), iv_hash);
    emit("setup.key", key_hash, 16);

    unsigned char decrypt_iv[16];
    unsigned char encrypt_iv[16];
    memcpy(decrypt_iv, iv_hash, 16);
    memcpy(encrypt_iv, iv_hash, 16);
    decrypt_iv[15]++;
    encrypt_iv[15] += 2;
    emit("setup.decrypt_iv", decrypt_iv, sizeof(decrypt_iv));
    emit("setup.encrypt_iv", encrypt_iv, sizeof(encrypt_iv));

    unsigned char client_public[32];
    sequence(client_public, sizeof(client_public));
    unsigned char server_public[32];
    for (int index = 0; index < 32; index++) {
        server_public[index] = (unsigned char)(index + 0x20);
    }

    unsigned char ciphertext[32];
    unsigned char tag[GCM_TAG_SIZE];
    gcm_encrypt(client_public, sizeof(client_public), ciphertext, key_hash, decrypt_iv, tag);
    emit("setup.request_epk", ciphertext, sizeof(ciphertext));
    emit("setup.request_tag", tag, sizeof(tag));

    gcm_encrypt(server_public, sizeof(server_public), ciphertext, key_hash, encrypt_iv, tag);
    emit("setup.reply_epk", ciphertext, sizeof(ciphertext));
    emit("setup.reply_tag", tag, sizeof(tag));

    unsigned char opened[32];
    int opened_length =
        gcm_decrypt(ciphertext, sizeof(ciphertext), opened, key_hash, encrypt_iv, tag);
    emit_int("setup.reply_opened_length", opened_length);
    emit("setup.reply_opened", opened, opened_length > 0 ? opened_length : 0);
}

/* ------------------------------------------------------------ FairPlay --- */

static void fairplay_vectors(void) {
    fairplay_t *fairplay = fairplay_init(logger);
    if (fairplay == NULL) {
        printf("fairplay.error = no session\n");
        return;
    }

    unsigned char request[16];
    memset(request, 0, sizeof(request));
    request[4] = 0x03;
    unsigned char response[142];
    memset(response, 0, sizeof(response));
    emit_int("fairplay.setup", fairplay_setup(fairplay, request, response));
    emit("fairplay.setup_response", response, sizeof(response));

    unsigned char handshake[164];
    memset(handshake, 0, sizeof(handshake));
    handshake[4] = 0x03;
    unsigned char handshake_response[32];
    memset(handshake_response, 0, sizeof(handshake_response));
    emit_int("fairplay.handshake", fairplay_handshake(fairplay, handshake, handshake_response));
    emit("fairplay.handshake_response", handshake_response, sizeof(handshake_response));

    unsigned char encrypted_key[72];
    sequence(encrypted_key, sizeof(encrypted_key));
    unsigned char decrypted_key[16];
    memset(decrypted_key, 0, sizeof(decrypted_key));
    emit_int("fairplay.decrypt", fairplay_decrypt(fairplay, encrypted_key, decrypted_key));
    emit("fairplay.decrypted_key", decrypted_key, sizeof(decrypted_key));

    fairplay_destroy(fairplay);
}

/* ------------------------------------------------------------ mirror --- */

/* The audio key and stream connection identifier the mirror vectors use. They are
 * fixed so the differential test can derive the same stream keys itself. */
static const uint64_t mirror_connection_id = 2765102747429192913ULL;
static const unsigned char mirror_audio_key[16] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
};

/* Packet lengths the vectors walk. The first two are the fixed vector from the
 * handoff: 40 bytes leaves eight keystream bytes of its tail block behind, and the
 * 24-byte packet that follows starts with them. */
static const int mirror_lengths[] = {40, 24, 33, 47, 1, 64, 5, 128};
static const int mirror_length_count =
    (int)(sizeof(mirror_lengths) / sizeof(mirror_lengths[0]));

/* Encrypts one packet with the keystream `model` says upstream's decryptor reads for
 * it: `mirror_buffer_decrypt` is an XOR with a keystream, so the bytes it XORs a
 * packet with are what any client has to have encrypted with. */
static void mirror_encrypt(const unsigned char *plaintext, int length,
                           const unsigned char *model, unsigned char *ciphertext) {
    for (int index = 0; index < length; index++) {
        ciphertext[index] = (unsigned char)(plaintext[index] ^ model[index]);
    }
}

static void mirror_vectors(void) {
    mirror_buffer_t *buffer = mirror_buffer_init(logger, mirror_audio_key);
    if (buffer == NULL) {
        printf("mirror.error = no buffer\n");
        return;
    }
    mirror_buffer_init_aes(buffer, &mirror_connection_id);

    /* The same key and IV the port derives, so the test can compare them. */
    unsigned char key_material[64] = {0};
    unsigned char iv_material[64] = {0};
    snprintf((char *)key_material, sizeof(key_material), "AirPlayStreamKey%" PRIu64,
             mirror_connection_id);
    snprintf((char *)iv_material, sizeof(iv_material), "AirPlayStreamIV%" PRIu64,
             mirror_connection_id);
    unsigned char key_hash[64];
    unsigned char iv_hash[64];
    sha512_labelled((const char *)key_material, mirror_audio_key, 16, key_hash);
    /* `sha512_labelled` hashes a label and a secret; the IV label is its own. */
    sha_ctx_t *ctx = sha_init();
    sha_update(ctx, (const uint8_t *)iv_material, (int)strlen((const char *)iv_material));
    sha_update(ctx, mirror_audio_key, 16);
    sha_final(ctx, iv_hash, NULL);
    sha_destroy(ctx);
    emit("mirror.key", key_hash, 16);
    emit("mirror.iv", iv_hash, 16);
    printf("mirror.connection_id = %" PRIu64 "\n", mirror_connection_id);

    /* The keystream blocks from the IV, so the test can check the port's own
     * generator block for block. */
    {
        aes_ctx_t *probe = aes_ctr_init(key_hash, iv_hash);
        unsigned char blocks[0x80 * 16];
        memset(blocks, 0, sizeof(blocks));
        aes_ctr_decrypt(probe, blocks, blocks, (int)sizeof(blocks));
        emit("mirror.keystream", blocks, sizeof(blocks));
        /* And far into the stream, which is where a session ends up: a generator whose
         * counter is wrong by one byte at the start is right at the start and wrong a
         * few thousand blocks in, and a picture that is noise says exactly that. The
         * block is the one a real session reached after its first packet. */
        aes_ctx_t *far = aes_ctr_init(key_hash, iv_hash);
        unsigned char skip[16];
        for (int waste = 0; waste < 3899; waste++) {
            aes_ctr_decrypt(far, skip, skip, 16);
        }
        unsigned char far_blocks[0x10 * 16];
        memset(far_blocks, 0, sizeof(far_blocks));
        aes_ctr_decrypt(far, far_blocks, far_blocks, (int)sizeof(far_blocks));
        emit("mirror.keystream_far", far_blocks, sizeof(far_blocks));
        aes_ctr_destroy(far);
        /* The counters themselves, for a range of blocks, printed as the cipher uses them.
         *
         * The keystream is the counter encrypted, so a port that encrypts the right counter
         * agrees with these by construction — and a port whose counter is built wrongly can
         * be compared with the number it should have been, which is a comparison the
         * keystream alone makes hard: the bytes look arbitrary either way, and a counter
         * that is short by one in a byte looks like nothing until the stream parts hundreds
         * of blocks later. The IV ends in `4f`, so block `b1` carries into the byte before
         * it, and that is where one port was 256 blocks out. */
        {
            static const int counter_blocks[] = {0, 1, 176, 177, 178, 255, 256, 257, 432, 433};
            const int counter_count =
                (int)(sizeof(counter_blocks) / sizeof(counter_blocks[0]));
            for (int which = 0; which < counter_count; which++) {
                uint64_t block = (uint64_t) counter_blocks[which];
                unsigned char counter[16];
                memcpy(counter, iv_hash, 16);
                /* The counter is the IV plus the block, big-endian, carried through the
                 * whole 128 bits — the same addition OpenSSL's CTR mode does. */
                uint64_t carry = block;
                for (int at = 15; at >= 0 && carry > 0; at--) {
                    uint64_t sum = (uint64_t) counter[at] + (carry & 0xff);
                    counter[at] = (unsigned char) (sum & 0xff);
                    carry = (carry >> 8) + (sum >> 8);
                }
                char label[64];
                snprintf(label, sizeof(label), "mirror.counter%d", counter_blocks[which]);
                emit(label, counter, 16);
            }
        }

        /* Six blocks, three either side of the place a long packet was measured to part at,
         * and three around the block it appeared to jump to. Printed together so the two
         * can be compared with a port's own generator rather than reasoned about. */
        {
            static const int wanted[] = {176, 177, 178, 432, 433, 434};
            aes_ctx_t *walk = aes_ctr_init(key_hash, iv_hash);
            unsigned char block[16];
            unsigned char zeros[16];
            for (int index = 0; index < 435; index++) {
                memset(zeros, 0, sizeof(zeros));
                aes_ctr_decrypt(walk, zeros, block, 16);
                for (int which = 0; which < 6; which++) {
                    if (wanted[which] == index) {
                        char label[64];
                        snprintf(label, sizeof(label), "mirror.block%d", index);
                        emit(label, block, 16);
                    }
                }
            }
            aes_ctr_destroy(walk);
        }
        aes_ctr_destroy(probe);
    }

    /* `mirror_buffer_decrypt` XORs a packet with keystream bytes, so decrypting a
     * packet of zeros prints exactly the bytes it reads — where in the stream they
     * are, for every packet length. That is the rule this port has to reproduce, and
     * the oracle emits it for the lengths the test walks. Each length gets a stream
     * of its own, so a vector is one packet and not a sequence. */
    for (int step = 0; step < mirror_length_count; step++) {
        int length = mirror_lengths[step];
        unsigned char input[512];
        unsigned char model[512];
        char label[64];
        memset(input, 0, sizeof(input));
        memset(model, 0, sizeof(model));
        mirror_buffer_t *reader = mirror_buffer_init(logger, mirror_audio_key);
        mirror_buffer_init_aes(reader, &mirror_connection_id);
        mirror_buffer_decrypt(reader, input, model, length);
        mirror_buffer_destroy(reader);
        snprintf(label, sizeof(label), "mirror.model%d", step);
        emit(label, model, length);
        snprintf(label, sizeof(label), "mirror.length%d", step);
        emit_int(label, length);
    }

    /* A sequence, which is the case the vectors above cannot reach: one stream read
     * packet after packet, which is what a session does. Each step decrypts zeros and
     * prints the bytes it read, so the position after every packet is visible — and a
     * port whose counter advances differently shows up at the step where the two
     * disagree rather than at the end. The lengths are a client's own: sizes that are
     * not multiples of the block, which is what leaves carried bytes behind. */
    {
        static const int sequence_lengths[] = {
            1356, 1358, 1356, 1355, 1346, 1300, 1400, 1420, 64, 33, 47, 1,
        };
        const int sequence_count =
            (int)(sizeof(sequence_lengths) / sizeof(sequence_lengths[0]));
        unsigned char input[4096];
        unsigned char model[4096];
        char label[64];
        mirror_buffer_t *reader = mirror_buffer_init(logger, mirror_audio_key);
        mirror_buffer_init_aes(reader, &mirror_connection_id);
        for (int step = 0; step < sequence_count; step++) {
            int length = sequence_lengths[step];
            memset(input, 0, sizeof(input));
            memset(model, 0, sizeof(model));
            mirror_buffer_decrypt(reader, input, model, length);
            /* The first bytes are where the reader is, which is the whole question,
             * and the length says which packet they belong to. */
            snprintf(label, sizeof(label), "mirror.sequence%d", step);
            emit(label, model, length > 64 ? 64 : length);
            snprintf(label, sizeof(label), "mirror.sequence_length%d", step);
            emit_int(label, length);
        }
        mirror_buffer_destroy(reader);
    }

    /* What a packet reads when it follows another one, which is the case a session is:
     * the reader is given the first length and then the second, and prints what it read
     * for the second. Adjacency and block alignment differ by at most fifteen bytes, so
     * the answer is the offset the bytes sit at, and a port can compare its own.
     *
     * The pairs are a client's own sizes, including a first packet of tens of kilobytes,
     * because that is what a session starts with. */
    {
        static const int pairs[][2] = {
            /* What each pair is for. The last four vary one thing at a time around the
             * pair that diverges, so the rule can be read off which of them still does. */
            {62415, 1265},  /* a first packet of a real session's size */
            {1265, 9710},   /* the one that diverges */
            {9710, 1237},   /* and one that does not, for contrast */
            {1356, 1355},
            {0, 8000},      /* no first packet at all: a long packet from the start */
            {0, 4000},      /* and one that does not reach the place the other parts at */
            {16, 8000},     /* one block first: does the place move with where it starts? */
            {256, 8000},    /* sixteen blocks */
            {0, 16000},     /* longer still */
            {0, 262144},    /* and far longer, to see if the shift repeats */
        };
        const int pair_count = (int)(sizeof(pairs) / sizeof(pairs[0]));
        unsigned char input[131072];
        unsigned char model[131072];
        unsigned char waste[131072];
        char label[64];
        for (int pair = 0; pair < pair_count; pair++) {
            int first = pairs[pair][0];
            int second = pairs[pair][1];
            mirror_buffer_t *reader = mirror_buffer_init(logger, mirror_audio_key);
            mirror_buffer_init_aes(reader, &mirror_connection_id);
            memset(input, 0, sizeof(input));
            memset(waste, 0, sizeof(waste));
            mirror_buffer_decrypt(reader, input, waste, first);
            memset(input, 0, sizeof(input));
            memset(model, 0, sizeof(model));
            mirror_buffer_decrypt(reader, input, model, second);
            mirror_buffer_destroy(reader);
            snprintf(label, sizeof(label), "mirror.pair_first%d", pair);
            emit_int(label, first);
            snprintf(label, sizeof(label), "mirror.pair_second%d", pair);
            emit_int(label, second);
            /* The whole answer, so a port can compare its own byte for byte rather
             * than search for it. */
            snprintf(label, sizeof(label), "mirror.pair_read%d", pair);
            emit(label, model, second);
        }
    }

    /* One long packet read from the start of the stream, which is the simplest case there
     * is: no packet before it, so no carry and no counter to restart — the reader is given
     * one length and reads it straight through.
     *
     * A divergence in the middle of that would be a property of the reader itself and of
     * nothing else, and the lengths here bracket where one appears to start. */
    {
        static const int single_lengths[] = {
            1024, 2048, 4000, 8000, 16000, 65536, 262144,
        };
        const int single_count = (int)(sizeof(single_lengths) / sizeof(single_lengths[0]));
        static unsigned char input[300000];
        static unsigned char model[300000];
        char label[64];
        for (int step = 0; step < single_count; step++) {
            int length = single_lengths[step];
            mirror_buffer_t *reader = mirror_buffer_init(logger, mirror_audio_key);
            mirror_buffer_init_aes(reader, &mirror_connection_id);
            memset(input, 0, sizeof(input));
            memset(model, 0, sizeof(model));
            mirror_buffer_decrypt(reader, input, model, length);
            mirror_buffer_destroy(reader);
            snprintf(label, sizeof(label), "mirror.single_length%d", step);
            emit_int(label, length);
            snprintf(label, sizeof(label), "mirror.single%d", step);
            emit(label, model, length);
        }
    }

    /* The sequence checked by upstream's own decryptor, byte for byte, without a
     * vector leaving this program.
     *
     * The check above prints the bytes each packet read, and a port compares them with
     * its own — which is how a wrong expectation gets copied into a test. Here the
     * expectation cannot be copied: the oracle encrypts a plaintext whose bytes it
     * knows, with the keystream a reader of its own reads for that packet, and then
     * checks that the persistent reader gives the plaintext back. If upstream's
     * decryptor is not self-consistent across a sequence, the line says which step.
     *
     * One byte per step also leaves the program, so a port can check its own run against
     * the same twelve bytes: the checksum of a step's plaintext, which is a number no
     * search can find in the wrong place. */
    {
        static const int self_lengths[] = {
            1356, 1358, 1356, 1355, 1346, 1300, 1400, 1420, 64, 33, 47, 1,
        };
        const int self_count = (int)(sizeof(self_lengths) / sizeof(self_lengths[0]));
        unsigned char plaintext[4096];
        unsigned char input[4096];
        unsigned char model[4096];
        unsigned char ciphertext[4096];
        unsigned char decrypted[4096];
        unsigned char checksums[64];
        char label[64];
        mirror_buffer_t *reader = mirror_buffer_init(logger, mirror_audio_key);
        mirror_buffer_init_aes(reader, &mirror_connection_id);
        bool consistent = true;
        for (int step = 0; step < self_count; step++) {
            int length = self_lengths[step];
            /* A plaintext of its own per step, so a step that reads the wrong part of
             * the stream cannot pass by agreeing with the step before it. */
            sequence(plaintext, length);
            for (int index = 0; index < length; index++) {
                plaintext[index] = (unsigned char)(plaintext[index] ^ (step * 31));
            }
            /* The keystream this packet is encrypted with: what a reader of its own
             * reads for the same length from a stream that starts where the vectors
             * start. */
            mirror_buffer_t *fresh = mirror_buffer_init(logger, mirror_audio_key);
            mirror_buffer_init_aes(fresh, &mirror_connection_id);
            memset(input, 0, sizeof(input));
            memset(model, 0, sizeof(model));
            mirror_buffer_decrypt(fresh, input, model, length);
            mirror_buffer_destroy(fresh);

            mirror_encrypt(plaintext, length, model, ciphertext);
            memset(decrypted, 0, sizeof(decrypted));
            memset(input, 0, sizeof(input));
            memcpy(input, ciphertext, (size_t)length);
            mirror_buffer_decrypt(reader, input, decrypted, length);
            if (memcmp(decrypted, plaintext, (size_t)length) != 0) {
                /* Reported as a value rather than logged: the verdict is the line
                 * below, and a log line would need a logger this check does not have. */
                consistent = false;
            }
            unsigned char checksum = 0;
            for (int index = 0; index < length; index++) {
                checksum = (unsigned char)(checksum + plaintext[index]);
            }
            checksums[step] = checksum;
        }
        mirror_buffer_destroy(reader);
        emit_int("mirror.self_consistent", consistent ? 1 : 0);
        emit("mirror.self_checksums", checksums, self_count);
    }

    /* And the round trip: a packet encrypted with that keystream has to come back
     * out of upstream's own decrypt unchanged. This is what says the keystream
     * above is the one a client's ciphertext is read with. */
    for (int step = 0; step < mirror_length_count; step++) {
        int length = mirror_lengths[step];
        unsigned char plaintext[512];
        unsigned char input[512];
        unsigned char ciphertext[512];
        unsigned char decrypted[512];
        unsigned char model[512];
        char label[64];
        sequence(plaintext, length);
        /* A buffer of its own for each call, so the model is read from a stream that
         * starts where the vectors start. Its input buffer is separate from its
         * output one, because upstream decrypts in place on the tail. */
        mirror_buffer_t *fresh = mirror_buffer_init(logger, mirror_audio_key);
        mirror_buffer_init_aes(fresh, &mirror_connection_id);
        memset(input, 0, sizeof(input));
        memset(model, 0, sizeof(model));
        mirror_buffer_decrypt(fresh, input, model, length);
        mirror_buffer_destroy(fresh);

        mirror_encrypt(plaintext, length, model, ciphertext);
        mirror_buffer_t *reader = mirror_buffer_init(logger, mirror_audio_key);
        mirror_buffer_init_aes(reader, &mirror_connection_id);
        memset(decrypted, 0, sizeof(decrypted));
        memset(input, 0, sizeof(input));
        memcpy(input, ciphertext, (size_t)length);
        mirror_buffer_decrypt(reader, input, decrypted, length);
        mirror_buffer_destroy(reader);
        snprintf(label, sizeof(label), "mirror.plaintext%d", step);
        emit(label, decrypted, length);
        snprintf(label, sizeof(label), "mirror.ciphertext%d", step);
        emit(label, ciphertext, length);
    }
    mirror_buffer_destroy(buffer);
}

int main(int argc, char **argv) {
    logger = logger_init();
    const char *mode = argc > 1 ? argv[1] : "crypto";
    if (strcmp(mode, "crypto") == 0) {
        crypto_vectors();
    } else if (strcmp(mode, "fairplay") == 0) {
        fairplay_vectors();
    } else if (strcmp(mode, "mirror") == 0) {
        mirror_vectors();
    } else if (strcmp(mode, "srp-init") == 0) {
        srp_init(argc > 2 && strcmp(argv[2], "short") == 0);
    } else if (strcmp(mode, "srp-verify") == 0) {
        srp_verify(argc, argv);
    } else {
        printf("usage: oracle [crypto|fairplay|mirror|srp-init [short]|srp-verify <salt> <verifier> <b> <A> <M>]\n");
    }
    logger_destroy(logger);
    return 0;
}
