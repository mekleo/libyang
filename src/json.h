/**
 * @file json.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Generic JSON format parser routines.
 *
 * Copyright (c) 2020 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef LY_JSON_H_
#define LY_JSON_H_

#include <stddef.h>
#include <stdint.h>

#include "log.h"
#include "set.h"

struct ly_ctx;
struct ly_out;
struct ly_prefix;

/* Macro to test if character is whitespace */
#define is_jsonws(c) (c == 0x20 || c == 0x9 || c == 0xa || c == 0xd)

/* Macro to test if character is valid string character */
#define is_jsonstrchar(c) (c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x10ffff))

/**
 * @brief Status of the parser providing information what is expected next (which function is supposed to be called).
 */
enum LYJSON_PARSER_STATUS {
    LYJSON_ROOT,           /* JSON document root, used internally */
    LYJSON_FALSE,          /* JSON false value */
    LYJSON_TRUE,           /* JSON true value */
    LYJSON_NULL,           /* JSON null value */
    LYJSON_OBJECT,         /* JSON object */
    LYJSON_OBJECT_CLOSED,  /* JSON object closed */
    LYJSON_OBJECT_EMPTY,   /* empty JSON object { }*/
    LYJSON_ARRAY,          /* JSON array */
    LYJSON_ARRAY_CLOSED,   /* JSON array closed */
    LYJSON_ARRAY_EMPTY,    /* empty JSON array */
    LYJSON_NUMBER,         /* JSON number value */
    LYJSON_STRING,         /* JSON string value */
    LYJSON_END             /* end of input data */
};

struct lyjson_ctx {

    struct ly_set status;   /* stack of LYJSON_PARSER_STATUS values corresponding to the JSON items being processed */

    const char *value;      /* LYJSON_STRING, LYJSON_NUMBER */
    size_t value_len;       /* LYJSON_STRING, LYJSON_NUMBER */
    int dynamic;            /* LYJSON_STRING, LYJSON_NUMBER */

#if 0
    union {
        const char *prefix; /* LYXML_ELEMENT, LYXML_ATTRIBUTE */
        const char *value;  /* LYXML_ELEM_CONTENT, LYXML_ATTR_CONTENT */
    };
    union {
        size_t prefix_len;  /* LYXML_ELEMENT, LYXML_ATTRIBUTE */
        size_t value_len;   /* LYXML_ELEM_CONTENT, LYXML_ATTR_CONTENT */
    };
    union {
        const char *name;   /* LYXML_ELEMENT, LYXML_ATTRIBUTE */
        int ws_only;        /* LYXML_ELEM_CONTENT, LYXML_ATTR_CONTENT */
    };
    union {
        size_t name_len;    /* LYXML_ELEMENT, LYXML_ATTRIBUTE */
        int dynamic;        /* LYXML_ELEM_CONTENT, LYXML_ATTR_CONTENT */
    };
#endif
    const struct ly_ctx *ctx;
    uint64_t line;
    const char *input;
};

/**
 * @brief Create a new JSON parser context and start parsing.
 *
 * @param[in] ctx libyang context.
 * @param[in] input JSON string data to parse.
 * @param[out] jsonctx New JSON context with status ::LYJSON_VALUE.
 * @return LY_ERR value.
 */
LY_ERR lyjson_ctx_new(const struct ly_ctx *ctx, const char *input, struct lyjson_ctx **jsonctx);

/**
 * @brief Get status of the parser as the last parsed token
 *
 * @param[in] jsonctx JSON context to check.
 */
enum LYJSON_PARSER_STATUS lyjson_ctx_status(struct lyjson_ctx *jsonctx);

/**
 * @brief Move to the next JSON artefact and update parser status.
 *
 * @param[in] jsonctx XML context to move.
 * @return LY_ERR value.
 */
LY_ERR lyjson_ctx_next(struct lyjson_ctx *jsonctx);

#if 0
/**
 * @brief Peek at the next XML parser status without changing it.
 *
 * @param[in] xmlctx XML context to use.
 * @param[out] next Next XML parser status.
 * @return LY_ERR value.
 */
LY_ERR lyxml_ctx_peek(struct lyxml_ctx *xmlctx, enum LYXML_PARSER_STATUS *next);

/**
 * @brief Get a namespace record for the given prefix in the current context.
 *
 * @param[in] xmlctx XML context to work with.
 * @param[in] prefix Pointer to the namespace prefix as taken from lyxml_get_attribute() or lyxml_get_element().
 * Can be NULL for default namespace.
 * @param[in] prefix_len Length of the prefix string (since it is not NULL-terminated when returned from lyxml_get_attribute() or
 * lyxml_get_element()).
 * @return The namespace record or NULL if the record for the specified prefix not found.
 */
const struct lyxml_ns *lyxml_ns_get(struct lyxml_ctx *xmlctx, const char *prefix, size_t prefix_len);

/**
 * @brief Print the given @p text as XML string which replaces some of the characters which cannot appear in XML data.
 *
 * @param[in] out Output structure for printing.
 * @param[in] text String to print.
 * @param[in] attribute Flag for attribute's value where a double quotes must be replaced.
 * @return LY_ERR values.
 */
LY_ERR lyxml_dump_text(struct ly_out *out, const char *text, int attribute);
#endif
/**
 * @brief Remove the allocated working memory of the context.
 *
 * @param[in] jsonctx JSON context to clear.
 */
void lyjson_ctx_free(struct lyjson_ctx *jsonctx);

#if 0
/**
 * @brief Find all possible prefixes in a value.
 *
 * @param[in] xmlctx XML context to use.
 * @param[in] value Value to check.
 * @param[in] value_len Value length.
 * @param[out] val_prefs Array of found prefixes.
 * @return LY_ERR value.
 */
LY_ERR lyxml_get_prefixes(struct lyxml_ctx *xmlctx, const char *value, size_t value_len, struct ly_prefix **val_prefs);

/**
 * @brief Compare values and their prefix mappings.
 *
 * @param[in] value1 First value.
 * @param[in] prefs1 First value prefixes.
 * @param[in] value2 Second value.
 * @param[in] prefs2 Second value prefixes.
 * @return LY_SUCCESS if values are equal.
 * @return LY_ENOT if values are not equal.
 * @return LY_ERR on error.
 */
LY_ERR lyjson_value_compare(const char *value1, const struct ly_prefix *prefs1, const char *value2,
                            const struct ly_prefix *prefs2);

#endif

#endif /* LY_JSON_H_ */
