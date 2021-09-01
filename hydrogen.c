/**
 * @file   hydrogen/hydrogen.c
 * @author Peter Züger
 * @date   25.01.2021
 * @brief  libhydrogen Micropython wrapper
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 Peter Züger
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "py/mpconfig.h"

#if defined(MODULE_HYDROGEN_ENABLED) && MODULE_HYDROGEN_ENABLED == 1

#include "py/misc.h"
#include "py/obj.h"
#include "py/objarray.h"
#include "py/objstr.h"
#include "py/runtime.h"

#include <lib/libhydrogen/hydrogen.h>

static void hydrogen_mp_obj_get_data(mp_obj_t data_p, uint8_t** data, size_t* size){
    if(mp_obj_is_type(data_p, &mp_type_bytearray) || mp_obj_is_type(data_p, &mp_type_memoryview)){
        *data = (uint8_t*)((mp_obj_array_t*)data_p)->items;
        *size = ((mp_obj_array_t*)data_p)->len;
    }else{
        // raises TypeError
        *data = (uint8_t*)mp_obj_str_get_data(data_p, size);
    }
}

mp_obj_t hydrogen_mp_obj_bytes(const uint8_t* data, size_t len){
    mp_obj_str_t *o = m_new_obj(mp_obj_str_t);
    o->base.type = &mp_type_bytes;
    o->data = data;
    o->len = len;
    o->hash = qstr_compute_hash(data, len);
    return MP_OBJ_FROM_PTR(o);
}

static const char* hydrogen_mp_obj_get_context(mp_obj_t context_in, size_t context_size){
    size_t size;

    // raises TypeError
    const char* context = mp_obj_str_get_data(context_in, &size);

    if(size != context_size){
        mp_raise_ValueError(MP_ERROR_TEXT("Context has the wrong size"));
    }

    return context;
}

typedef struct _hydrogen_hash_obj_t{
    // base represents some basic information, like type
    mp_obj_base_t base;

    hydro_hash_state st;
}hydrogen_hash_obj_t;


mp_obj_t hydrogen_hash_make_new(const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* args);
STATIC void hydrogen_hash_print(const mp_print_t* print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t hydrogen_hash_update(mp_obj_t self_in, mp_obj_t data_in);
STATIC mp_obj_t hydrogen_hash_final(size_t n_args, const mp_obj_t* args);

STATIC MP_DEFINE_CONST_FUN_OBJ_2(hydrogen_hash_update_fun_obj, hydrogen_hash_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_hash_final_fun_obj, 1, 2, hydrogen_hash_final);


STATIC const mp_rom_map_elem_t hydrogen_hash_locals_dict_table[]={
    // class methods
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&hydrogen_hash_update_fun_obj) },
    { MP_ROM_QSTR(MP_QSTR_final),  MP_ROM_PTR(&hydrogen_hash_final_fun_obj)  },
};
STATIC MP_DEFINE_CONST_DICT(hydrogen_hash_locals_dict,hydrogen_hash_locals_dict_table);


const mp_obj_type_t hydrogen_hash_type={
    // "inherit" the type "type"
    { &mp_type_type },
    // give it a name
    .name = MP_QSTR_hash,
    // give it a print-function
    .print = hydrogen_hash_print,
    // give it a constructor
    .make_new = hydrogen_hash_make_new,
    // and the global members
    .locals_dict = (mp_obj_dict_t*)&hydrogen_hash_locals_dict,
};

/**
 * Python: hydrogen.hash(context, key=None)
 * @param context
 * @param key
 */
mp_obj_t hydrogen_hash_make_new(const mp_obj_type_t* type,
                                size_t n_args,
                                size_t n_kw,
                                const mp_obj_t* args){
    mp_arg_check_num(n_args, n_kw, 1, 2, false);

    // raises MemoryError
    hydrogen_hash_obj_t* self = m_new_obj(hydrogen_hash_obj_t);

    self->base.type = &hydrogen_hash_type;

    // raises TypeError, ValueError
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_hash_CONTEXTBYTES);

    size_t key_size;
    uint8_t* key = NULL;

    if(n_args == 2 && args[1] != mp_const_none){
        // raises TypeError
        hydrogen_mp_obj_get_data(args[1], &key, &key_size);

        if(key_size != hydro_hash_KEYBYTES){
            mp_raise_ValueError(MP_ERROR_TEXT("Key has the wrong size"));
        }
    }

    hydro_hash_init(&self->st, context, key);

    return MP_OBJ_FROM_PTR(self);
}

/**
 * Python: print(hydrogen.hash(context, key))
 * @param obj
 */
STATIC void hydrogen_hash_print(const mp_print_t* print,
                                mp_obj_t self_in, mp_print_kind_t kind){
    //hydrogen_hash_obj_t* self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "hash()");
}

/**
 * Python: hydrogen.hash.update(self, data)
 * @param self
 * @param data
 */
STATIC mp_obj_t hydrogen_hash_update(mp_obj_t self_in, mp_obj_t data_in){
    hydrogen_hash_obj_t* self = MP_OBJ_TO_PTR(self_in);

    size_t size;
    uint8_t* data;

    // raises TypeError
    hydrogen_mp_obj_get_data(data_in, &data, &size);

    hydro_hash_update(&self->st, data, size);

    return mp_const_none;
}

/**
 * Python: hydrogen.hash.final(self[, hash_size])
 * @param self
 * @param hash_size
 */
STATIC mp_obj_t hydrogen_hash_final(size_t n_args, const mp_obj_t* args){
    hydrogen_hash_obj_t* self = MP_OBJ_TO_PTR(args[0]);

    size_t size = hydro_hash_BYTES;

    if(n_args == 2){
        // raises TypeError
        size = mp_obj_get_int(args[1]);

        if((size < hydro_hash_BYTES_MIN) || (size > hydro_hash_BYTES_MAX)){
            mp_raise_ValueError(MP_ERROR_TEXT("Hash size out of range"));
        }
    }

    uint8_t* hash = m_malloc(size);

    hydro_hash_final(&self->st, hash, size);

    return hydrogen_mp_obj_bytes(hash, size);
}


typedef struct _hydrogen_sign_obj_t{
    // base represents some basic information, like type
    mp_obj_base_t base;

    hydro_sign_state st;
}hydrogen_sign_obj_t;


mp_obj_t hydrogen_sign_make_new(const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* args);
STATIC void hydrogen_sign_print(const mp_print_t* print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t hydrogen_sign_update(mp_obj_t self_in, mp_obj_t data_in);
STATIC mp_obj_t hydrogen_sign_final_create(mp_obj_t self_in, mp_obj_t key_in);
STATIC mp_obj_t hydrogen_sign_final_verify(mp_obj_t self_in, mp_obj_t signature_in, mp_obj_t key_in);

STATIC MP_DEFINE_CONST_FUN_OBJ_2(hydrogen_sign_update_fun_obj, hydrogen_sign_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(hydrogen_sign_final_create_fun_obj, hydrogen_sign_final_create);
STATIC MP_DEFINE_CONST_FUN_OBJ_3(hydrogen_sign_final_verify_fun_obj, hydrogen_sign_final_verify);

STATIC const mp_rom_map_elem_t hydrogen_sign_locals_dict_table[]={
    // class methods
    { MP_ROM_QSTR(MP_QSTR_update),       MP_ROM_PTR(&hydrogen_sign_update_fun_obj)       },
    { MP_ROM_QSTR(MP_QSTR_final_create), MP_ROM_PTR(&hydrogen_sign_final_create_fun_obj) },
    { MP_ROM_QSTR(MP_QSTR_final_verify), MP_ROM_PTR(&hydrogen_sign_final_verify_fun_obj) },
};
STATIC MP_DEFINE_CONST_DICT(hydrogen_sign_locals_dict,hydrogen_sign_locals_dict_table);


const mp_obj_type_t hydrogen_sign_type={
    // "inherit" the type "type"
    { &mp_type_type },
    // give it a name
    .name = MP_QSTR_sign,
    // give it a print-function
    .print = hydrogen_sign_print,
    // give it a constructor
    .make_new = hydrogen_sign_make_new,
    // and the global members
    .locals_dict = (mp_obj_dict_t*)&hydrogen_sign_locals_dict,
};

/**
 * Python: hydrogen.sign(context)
 * @param context
 */
mp_obj_t hydrogen_sign_make_new(const mp_obj_type_t* type,
                                size_t n_args,
                                size_t n_kw,
                                const mp_obj_t* args){
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    // raises MemoryError
    hydrogen_sign_obj_t* self = m_new_obj(hydrogen_sign_obj_t);

    self->base.type = &hydrogen_sign_type;

    // raises TypeError, ValueError
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_sign_CONTEXTBYTES);

    hydro_sign_init(&self->st, context);

    return MP_OBJ_FROM_PTR(self);
}

/**
 * Python: print(hydrogen.sign(context))
 * @param obj
 */
STATIC void hydrogen_sign_print(const mp_print_t* print,
                                mp_obj_t self_in, mp_print_kind_t kind){
    //hydrogen_sign_obj_t* self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "sign()");
}

/**
 * Python: hydrogen.sign.update(self, data)
 * @param self
 * @param data
 */
STATIC mp_obj_t hydrogen_sign_update(mp_obj_t self_in, mp_obj_t data_in){
    hydrogen_sign_obj_t* self = MP_OBJ_TO_PTR(self_in);

    size_t size;
    uint8_t* data;

    // raises TypeError
    hydrogen_mp_obj_get_data(data_in, &data, &size);

    hydro_sign_update(&self->st, data, size);

    return mp_const_none;
}

/**
 * Python: hydrogen.sign.final_create(self, key)
 * @param self
 * @param key
 */
STATIC mp_obj_t hydrogen_sign_final_create(mp_obj_t self_in, mp_obj_t key_in){
    hydrogen_sign_obj_t* self = MP_OBJ_TO_PTR(self_in);

    size_t key_size;
    uint8_t* key;

    // raises TypeError
    hydrogen_mp_obj_get_data(key_in, &key, &key_size);

    if(key_size != hydro_sign_SECRETKEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Secret Key has the wrong size"));
    }

    uint8_t* signature = m_malloc(hydro_sign_BYTES);

    hydro_sign_final_create(&self->st, signature, key);

    return hydrogen_mp_obj_bytes(signature, hydro_sign_BYTES);
}

/**
 * Python: hydrogen.sign.final_verify(self, signature, key)
 * @param self
 * @param signature
 * @param key
 */
STATIC mp_obj_t hydrogen_sign_final_verify(mp_obj_t self_in, mp_obj_t signature_in, mp_obj_t key_in){
    hydrogen_sign_obj_t* self = MP_OBJ_TO_PTR(self_in);

    size_t signature_size;
    uint8_t* signature;

    // raises TypeError
    hydrogen_mp_obj_get_data(signature_in, &signature, &signature_size);

    if(signature_size != hydro_sign_BYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Signature has the wrong size"));
    }

    size_t key_size;
    uint8_t* key;

    // raises TypeError
    hydrogen_mp_obj_get_data(key_in, &key, &key_size);

    if(key_size != hydro_sign_PUBLICKEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Public Key has the wrong size"));
    }

    if(hydro_sign_final_verify(&self->st, signature, key) != 0){
        return mp_const_false;
    }
    return mp_const_true;
}

/**
 * Python: hydrogen.init()
 */
STATIC mp_obj_t hydrogen_init(void){
    if(hydro_init() != 0){
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("hydro_init() failed"));
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_init_fun_obj, hydrogen_init);

/**
 * Python: hydrogen.random_u32()
 */
STATIC mp_obj_t hydrogen_random_u32(void){
    return mp_obj_new_int(hydro_random_u32());
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_random_u32_fun_obj, hydrogen_random_u32);

/**
 * Python: hydrogen.random_uniform(upper_bound)
 * @param upper_bound
 */
STATIC mp_obj_t hydrogen_random_uniform(mp_obj_t upper_bound){
    // raises TypeError
    return mp_obj_new_int(hydro_random_uniform(mp_obj_get_int(upper_bound)));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(hydrogen_random_uniform_fun_obj, hydrogen_random_uniform);

/**
 * Python: hydrogen.random_buf(len)
 * @param len
 */
STATIC mp_obj_t hydrogen_random_buf(mp_obj_t len_in){
    // raises TypeError
    size_t len = mp_obj_get_int(len_in);

    uint8_t* data = m_malloc(len);

    hydro_random_buf(data, len);

    return hydrogen_mp_obj_bytes(data, len);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(hydrogen_random_buf_fun_obj, hydrogen_random_buf);

/**
 * Python: hydrogen.random_ratchet()
 */
STATIC mp_obj_t hydrogen_random_ratchet(void){
    hydro_random_ratchet();
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_random_ratchet_fun_obj, hydrogen_random_ratchet);

/**
 * Python: hydrogen.random_reseed()
 */
STATIC mp_obj_t hydrogen_random_reseed(void){
    hydro_random_reseed();
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_random_reseed_fun_obj, hydrogen_random_reseed);

/**
 * Python: hydrogen.hash_hash(context, data, key=None[, hash_size])
 * @param context
 * @param data
 * @param key
 * @param hash_size
 */
STATIC mp_obj_t hydrogen_hash_hash(size_t n_args, const mp_obj_t *args){
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_hash_CONTEXTBYTES);

    size_t size;
    uint8_t* data;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[1], &data, &size);

    size_t key_size;
    uint8_t* key = NULL;

    if(n_args >= 3 && args[2] != mp_const_none){
        // raises TypeError
        hydrogen_mp_obj_get_data(args[2], &key, &key_size);

        if(key_size != hydro_hash_KEYBYTES){
            mp_raise_ValueError(MP_ERROR_TEXT("Key has the wrong size"));
        }
    }

    size_t hash_size = hydro_hash_BYTES;

    if(n_args == 4){
        // raises TypeError
        hash_size = mp_obj_get_int(args[3]);

        if((hash_size < hydro_hash_BYTES_MIN) || (hash_size > hydro_hash_BYTES_MAX)){
            mp_raise_ValueError(MP_ERROR_TEXT("Hash size out of range"));
        }
    }

    uint8_t* hash = m_malloc(hash_size);

    hydro_hash_hash(hash, hash_size, data, size, context, key);

    return hydrogen_mp_obj_bytes(hash, hash_size);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_hash_hash_fun_obj, 2, 4, hydrogen_hash_hash);

/**
 * Python: hydrogen.hash_keygen()
 */
STATIC mp_obj_t hydrogen_hash_keygen(void){
    uint8_t* key_buf = m_malloc(hydro_hash_KEYBYTES);

    hydro_hash_keygen(key_buf);

    return hydrogen_mp_obj_bytes(key_buf, hydro_hash_KEYBYTES);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_hash_keygen_fun_obj, hydrogen_hash_keygen);

/**
 * Python: hydrogen.kdf_keygen()
 */
STATIC mp_obj_t hydrogen_kdf_keygen(void){
    uint8_t* key_buf = m_malloc(hydro_kdf_KEYBYTES);

    hydro_kdf_keygen(key_buf);

    return hydrogen_mp_obj_bytes(key_buf, hydro_kdf_KEYBYTES);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_kdf_keygen_fun_obj, hydrogen_kdf_keygen);

/**
 * Python: hydrogen.kdf_derive_from_key(context, master_key, subkey_id[, subkey_len])
 * @param context
 * @param master_key
 * @param subkey_id
 * @param subkey_len
 */
STATIC mp_obj_t hydrogen_kdf_derive_from_key(size_t n_args, const mp_obj_t *args){
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_kdf_CONTEXTBYTES);

    size_t master_size;
    uint8_t* master_key;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[1], &master_key, &master_size);

    if(master_size != hydro_kdf_KEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Master key has the wrong size"));
    }

    // raises TypeError
    uint64_t subkey_id = mp_obj_get_int(args[2]);

    size_t subkey_size = hydro_kdf_KEYBYTES;

    if(n_args == 4){
        // raises TypeError
        subkey_size = mp_obj_get_int(args[3]);

        if((subkey_size < hydro_kdf_BYTES_MIN) || (subkey_size > hydro_kdf_BYTES_MAX)){
            mp_raise_ValueError(MP_ERROR_TEXT("Subkey size out of range"));
        }
    }

    uint8_t* subkey_buf = m_malloc(subkey_size);

    hydro_kdf_derive_from_key(subkey_buf, subkey_size, subkey_id, context, master_key);

    return hydrogen_mp_obj_bytes(subkey_buf, subkey_size);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_kdf_derive_from_key_fun_obj, 3, 4, hydrogen_kdf_derive_from_key);

/**
 * Python: hydrogen.secretbox_keygen()
 */
STATIC mp_obj_t hydrogen_secretbox_keygen(void){
    uint8_t* key = m_malloc(hydro_secretbox_KEYBYTES);

    hydro_secretbox_keygen(key);

    return hydrogen_mp_obj_bytes(key, hydro_secretbox_KEYBYTES);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_secretbox_keygen_fun_obj, hydrogen_secretbox_keygen);

/**
 * Python: hydrogen.secretbox_encrypt(context, key, msg[, msg_id])
 * @param context
 * @param key
 * @param msg
 * @param msg_id
 */
STATIC mp_obj_t hydrogen_secretbox_encrypt(size_t n_args, const mp_obj_t *args){
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_secretbox_CONTEXTBYTES);

    size_t key_size;
    uint8_t* key;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[1], &key, &key_size);

    if(key_size != hydro_secretbox_KEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Key has the wrong size"));
    }

    size_t msg_size;
    uint8_t* msg;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[2], &msg, &msg_size);

    uint64_t msg_id = 0;

    if(n_args == 4){
        // raises TypeError
        msg_id = mp_obj_get_int(args[3]);
    }

    size_t ciphertext_size = hydro_secretbox_HEADERBYTES + msg_size;
    uint8_t* ciphertext = m_malloc(ciphertext_size);

    hydro_secretbox_encrypt(ciphertext, msg, msg_size, msg_id, context, key);

    return hydrogen_mp_obj_bytes(ciphertext, ciphertext_size);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_secretbox_encrypt_fun_obj, 3, 4, hydrogen_secretbox_encrypt);

/**
 * Python: hydrogen.secretbox_decrypt(context, key, ciphertext[, msg_id])
 * @param context
 * @param key
 * @param ciphertext
 * @param msg_id
 */
STATIC mp_obj_t hydrogen_secretbox_decrypt(size_t n_args, const mp_obj_t *args){
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_secretbox_CONTEXTBYTES);

    size_t key_size;
    uint8_t* key;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[1], &key, &key_size);

    if(key_size != hydro_secretbox_KEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Key has the wrong size"));
    }

    size_t ciphertext_size;
    uint8_t* ciphertext;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[2], &ciphertext, &ciphertext_size);

    uint64_t msg_id = 0;

    if(n_args == 4){
        // raises TypeError
        msg_id = mp_obj_get_int(args[3]);
    }

    size_t msg_size = ciphertext_size - hydro_secretbox_HEADERBYTES;
    uint8_t* msg = m_malloc(msg_size);

    int ret = hydro_secretbox_decrypt(msg, ciphertext, ciphertext_size, msg_id, context, key);

    if(ret != 0){
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("Authentication tag invalid"));
    }

    return hydrogen_mp_obj_bytes(msg, msg_size);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_secretbox_decrypt_fun_obj, 3, 4, hydrogen_secretbox_decrypt);

/**
 * Python: hydrogen.secretbox_probe_create(context, key, ciphertext)
 * @param context
 * @param key
 * @param ciphertext
 */
STATIC mp_obj_t hydrogen_secretbox_probe_create(size_t n_args, const mp_obj_t *args){
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_secretbox_CONTEXTBYTES);

    size_t key_size;
    uint8_t* key;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[1], &key, &key_size);

    if(key_size != hydro_secretbox_KEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Key has the wrong size"));
    }

    size_t ciphertext_size;
    uint8_t* ciphertext;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[2], &ciphertext, &ciphertext_size);

    uint8_t* probe = m_malloc(hydro_secretbox_PROBEBYTES);

    hydro_secretbox_probe_create(probe, ciphertext, ciphertext_size, context, key);

    return hydrogen_mp_obj_bytes(probe, hydro_secretbox_PROBEBYTES);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_secretbox_probe_create_fun_obj, 3, 3, hydrogen_secretbox_probe_create);

/**
 * Python: hydrogen.secretbox_probe_verify(context, key, ciphertext, probe)
 * @param context
 * @param key
 * @param ciphertext
 * @param probe
 */
STATIC mp_obj_t hydrogen_secretbox_probe_verify(size_t n_args, const mp_obj_t *args){
    const char* context = hydrogen_mp_obj_get_context(args[0], hydro_secretbox_CONTEXTBYTES);

    size_t key_size;
    uint8_t* key;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[1], &key, &key_size);

    if(key_size != hydro_secretbox_KEYBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Key has the wrong size"));
    }

    size_t ciphertext_size;
    uint8_t* ciphertext;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[2], &ciphertext, &ciphertext_size);

    size_t probe_size;
    uint8_t* probe;

    // raises TypeError
    hydrogen_mp_obj_get_data(args[3], &probe, &probe_size);

    if(probe_size != hydro_secretbox_PROBEBYTES){
        mp_raise_ValueError(MP_ERROR_TEXT("Probe has the wrong size"));
    }

    return mp_obj_new_bool(!hydro_secretbox_probe_verify(probe, ciphertext, ciphertext_size, context, key));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hydrogen_secretbox_probe_verify_fun_obj, 4, 4, hydrogen_secretbox_probe_verify);

/**
 * Python: hydrogen.sign_keygen()
 */
STATIC mp_obj_t hydrogen_sign_keygen(void){
    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);

    mp_obj_t tuple[2] = {
        mp_obj_new_bytes(key_pair.pk, hydro_sign_PUBLICKEYBYTES),
        mp_obj_new_bytes(key_pair.sk, hydro_sign_SECRETKEYBYTES),
    };

    hydro_memzero(&key_pair, hydro_sign_PUBLICKEYBYTES + hydro_sign_SECRETKEYBYTES);

    return mp_obj_new_tuple(2, tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(hydrogen_sign_keygen_fun_obj, hydrogen_sign_keygen);


STATIC const mp_obj_tuple_t hydrogen_version_obj = {
    {&mp_type_tuple},
    2,
    {
        MP_OBJ_NEW_SMALL_INT(HYDRO_VERSION_MAJOR),
        MP_OBJ_NEW_SMALL_INT(HYDRO_VERSION_MINOR)
    }
};

STATIC const mp_rom_map_elem_t hydrogen_globals_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___name__),               MP_OBJ_NEW_QSTR(MP_QSTR_hydrogen)                    },
    { MP_OBJ_NEW_QSTR(MP_QSTR_version),                MP_ROM_PTR(&hydrogen_version_obj)                    },

#if HYDRO_INIT_ON_IMPORT
#if MICROPY_MODULE_BUILTIN_INIT
    { MP_ROM_QSTR(MP_QSTR___init__),                   MP_ROM_PTR(&hydrogen_init_fun_obj)                   },
#else
#error "__init__ not enabled: set MICROPY_MODULE_BUILTIN_INIT=1 to enable"
#endif
#endif

    { MP_OBJ_NEW_QSTR(MP_QSTR_hash_BYTES),             MP_ROM_INT(hydro_hash_BYTES)                         },
    { MP_OBJ_NEW_QSTR(MP_QSTR_hash_BYTES_MIN),         MP_ROM_INT(hydro_hash_BYTES_MIN)                     },
    { MP_OBJ_NEW_QSTR(MP_QSTR_hash_BYTES_MAX),         MP_ROM_INT(hydro_hash_BYTES_MAX)                     },
    { MP_OBJ_NEW_QSTR(MP_QSTR_kdf_KEYBYTES),           MP_ROM_INT(hydro_kdf_KEYBYTES)                       },
    { MP_OBJ_NEW_QSTR(MP_QSTR_kdf_BYTES_MIN),          MP_ROM_INT(hydro_kdf_BYTES_MIN)                      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_kdf_BYTES_MAX),          MP_ROM_INT(hydro_kdf_BYTES_MAX)                      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_secretbox_KEYBYTES),     MP_ROM_INT(hydro_secretbox_KEYBYTES)                 },

    { MP_OBJ_NEW_QSTR(MP_QSTR_init),                   MP_ROM_PTR(&hydrogen_init_fun_obj)                   },
    { MP_OBJ_NEW_QSTR(MP_QSTR_random_u32),             MP_ROM_PTR(&hydrogen_random_u32_fun_obj)             },
    { MP_OBJ_NEW_QSTR(MP_QSTR_random_uniform),         MP_ROM_PTR(&hydrogen_random_uniform_fun_obj)         },
    { MP_OBJ_NEW_QSTR(MP_QSTR_random_buf),             MP_ROM_PTR(&hydrogen_random_buf_fun_obj)             },
    { MP_OBJ_NEW_QSTR(MP_QSTR_random_ratchet),         MP_ROM_PTR(&hydrogen_random_ratchet_fun_obj)         },
    { MP_OBJ_NEW_QSTR(MP_QSTR_random_reseed),          MP_ROM_PTR(&hydrogen_random_reseed_fun_obj)          },
    { MP_OBJ_NEW_QSTR(MP_QSTR_hash_hash),              MP_ROM_PTR(&hydrogen_hash_hash_fun_obj)              },
    { MP_OBJ_NEW_QSTR(MP_QSTR_hash_keygen),            MP_ROM_PTR(&hydrogen_hash_keygen_fun_obj)            },
    { MP_OBJ_NEW_QSTR(MP_QSTR_kdf_keygen),             MP_ROM_PTR(&hydrogen_kdf_keygen_fun_obj)             },
    { MP_OBJ_NEW_QSTR(MP_QSTR_kdf_derive_from_key),    MP_ROM_PTR(&hydrogen_kdf_derive_from_key_fun_obj)    },
    { MP_OBJ_NEW_QSTR(MP_QSTR_secretbox_keygen),       MP_ROM_PTR(&hydrogen_secretbox_keygen_fun_obj)       },
    { MP_OBJ_NEW_QSTR(MP_QSTR_secretbox_encrypt),      MP_ROM_PTR(&hydrogen_secretbox_encrypt_fun_obj)      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_secretbox_decrypt),      MP_ROM_PTR(&hydrogen_secretbox_decrypt_fun_obj)      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_secretbox_probe_create), MP_ROM_PTR(&hydrogen_secretbox_probe_create_fun_obj) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_secretbox_probe_verify), MP_ROM_PTR(&hydrogen_secretbox_probe_verify_fun_obj) },

    { MP_OBJ_NEW_QSTR(MP_QSTR_sign_keygen),            MP_ROM_PTR(&hydrogen_sign_keygen_fun_obj)            },

    { MP_OBJ_NEW_QSTR(MP_QSTR_hash),                   MP_ROM_PTR(&hydrogen_hash_type)                      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_sign),                   MP_ROM_PTR(&hydrogen_sign_type)                      },
};

STATIC MP_DEFINE_CONST_DICT(
    mp_module_hydrogen_globals,
    hydrogen_globals_table
    );

const mp_obj_module_t mp_module_hydrogen = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_hydrogen_globals,
};

MP_REGISTER_MODULE(MP_QSTR_hydrogen, mp_module_hydrogen, MODULE_HYDROGEN_ENABLED);

#endif /* defined(MODULE_HYDROGEN_ENABLED) && MODULE_HYDROGEN_ENABLED == 1 */
