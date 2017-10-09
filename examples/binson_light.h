/*
 *  Copyright (c) 2015 ASSA ABLOY AB
 *
 *  This file is part of binson-c-light, BINSON serialization format library in C.
 *
 *  binson-c-light is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU Lesser General Public License (LGPL) as published
 *  by the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  As a special exception, the Contributors give you permission to link
 *  this library with independent modules to produce an executable,
 *  regardless of the license terms of these independent modules, and to
 *  copy and distribute the resulting executable under terms of your choice,
 *  provided that you also meet, for each linked independent module, the
 *  terms and conditions of the license of that module. An independent
 *  module is a module which is not derived from or based on this library.
 *  If you modify this library, you must extend this exception to your
 *  version of the library.
 *
 *  binson-c-light is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 *  License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BINSON_LIGHT_H_INCLUDED
#define BINSON_LIGHT_H_INCLUDED

#ifdef WITH_TO_STRING
#include <stdio.h>
#endif

#include <stdint.h>
#include <string.h>

typedef uint16_t binson_tok_size;    /* type to keep token length (key and value are separate tokens). */
typedef uint16_t binson_size;        /* type to keep raw data block sizes and offsets */
typedef uint32_t binson_large_size;  /* type to keep counters etc, when 'binson_size' isn't enough */

#ifndef bool
#define bool        int   /* for 8-bit platforms better to use int8_t instead */
#define true        1
#define false       0
#endif

/*********** static config values ************/
#ifndef MAX_DEPTH   /* maximal supported binson object/array nesting level */
#define MAX_DEPTH   16       
#endif

#ifdef WITH_TO_STRING
#ifndef INDENT_WIDTH
#define INDENT_WIDTH  3
#endif
#endif

/*********************************************/
#define BINSON_ID_UNKNOWN        0x00
#define BINSON_ID_OBJECT         0x01
#define BINSON_ID_ARRAY 	       0x02
#define BINSON_ID_BLOCK          0x03  /* Meta ID. BINSON_ID_OBJECT or BINSON_ID_ARRAY */

#define BINSON_ID_OBJ_BEGIN      0x40
#define BINSON_ID_OBJ_END        0x41
#define BINSON_ID_ARRAY_BEGIN    0x42
#define BINSON_ID_ARRAY_END      0x43

#define BINSON_ID_BOOLEAN        0x47  /* Meta ID. Translated to one of 2 next consts during serialization */
#define BINSON_ID_TRUE           0x44
#define BINSON_ID_FALSE          0x45
#define BINSON_ID_DOUBLE         0x46

#define BINSON_ID_INTEGER        0x0f  /* Meta ID. Translated to one of 4 next consts during serialization */
#define BINSON_ID_INTEGER_8      0x10
#define BINSON_ID_INTEGER_16     0x11
#define BINSON_ID_INTEGER_32     0x12
#define BINSON_ID_INTEGER_64     0x13

#define BINSON_ID_STRING         0x12  /* Meta ID. Translated to one of 4 next consts during serialization */
#define BINSON_ID_STRING_LEN	   0x13  /* indicates stringLen part of STRING object */
#define BINSON_ID_STRING_8       0x14
#define BINSON_ID_STRING_16      0x15
#define BINSON_ID_STRING_32      0x16

#define BINSON_ID_BYTES          0x16  /* Meta ID. Translated to one of 3 next consts during serialization */
#define BINSON_ID_BYTES_LEN      0x17  /* indicates bytesLen part of BYTES object */
#define BINSON_ID_BYTES_8        0x18
#define BINSON_ID_BYTES_16       0x19
#define BINSON_ID_BYTES_32       0x1a

/* error codes */
#define BINSON_ID_OK	 		                0x00
#define BINSON_ID_INVALID_ARG             0xe0
#define BINSON_ID_BUF_FULL	 	            0xf0
#define BINSON_ID_PARSE_NO_FIELD_NAME	    0xf1
#define BINSON_ID_PARSE_BLOCK_ENDED  	    0xf2
#define BINSON_ID_PARSE_WRONG_STATE	      0xf3
#define BINSON_ID_PARSE_WRONG_TYPE	      0xf4
#define BINSON_ID_PARSE_BAD_LEN		        0xf5
#define BINSON_ID_PARSE_END_OF_BUFFER     0xf6
#define BINSON_ID_PARSE_MAX_DEPTH_REACHED 0xf7

/* parser configuration flags */
#define BINSON_PARSER_CFG_NONE                     0x00
#define BINSON_PARSER_CFG_INIT_AUTO_ADVANCE        0x01

/* scan modes used with binson_parser_advance() */
/* OBJECT/ARRAY begin/end tags, also name:val all are single items */
#define BINSON_PARSER_ADVANCE_N                    0x01  /* advance n items */
#define BINSON_PARSER_ADVANCE_N_SAME_DEPTH         0x02  /* advance n items, skipping nested */
#define BINSON_PARSER_ADVANCE_N_DEPTH              0x04  /* advance from current depth to depth+n */
#define BINSON_PARSER_ADVANCE_CMP_NAME             0x08  /* field search */
#define BINSON_PARSER_ADVANCE_ENSURE_TYPE          0x10  /* additional check of binson type when other requirements met */

/*********** usefull macros ******************/
#define SETBITMASK(x,y)   (x |= (y))  /* Set bitmask y in byte x*/
#define CLEARBITMASK(x,y)   (x &= (~y))   /* Clear bitmask y in byte x*/
#define CHECKBITMASK(x,y)   (x & (y))   /* Check bitmask y in byte x*/

#define SETBIT(x,b)     (x |= (1<<b))
#define CLEARBIT(x,b)     (x &= ~(1<<b))
#define CHECKBIT(x,b)     (x & (1<<b))

#define UNUSED(x) (void)(x)   /* for unused variable warning suppression */

#define OK(res) (res == BINSON_ID_OK)
#define IS_CLEAN(x) (x->error_flags == BINSON_ID_OK ? 1:0)
/*********************************************/

/* buffer pointer + size aggregation, also used for string references */
typedef struct _bbuf
{
  binson_tok_size	  bsize;
  uint8_t          *bptr;

} bbuf;

/* composite value types located in same memory bytes */
typedef union _binson_value
{
    int64_t   int_val;
    double    double_val;
    bool      bool_val;
    bbuf      bbuf_val;

} binson_value;

/* smart buffer structure used for both writer and parser */
typedef struct _binson_io
{
  binson_size  	buf_size;
  binson_size   buf_used;
  uint8_t      *pbuf;

  binson_large_size  counter;

} binson_io;

/*======================== WRITER ===============================*/

/* main writer "object" structure */
typedef struct _binson_writer
{
  uint8_t	      error_flags;
  binson_io     io;  	      /* smart buffer */
  binson_value  tmp_val;    /* used to simplify passing simple types to/from meta functions */

} binson_writer;

/* writer object initialization / reset */
void binson_writer_init( binson_writer *pw, uint8_t *pbuf, binson_size buf_size  );
void binson_writer_reset( binson_writer *pw );
void binson_writer_purge( binson_writer *pw );

/* writer public methods */
void binson_write_object_begin( binson_writer *pw );
void binson_write_object_end( binson_writer *pw );
void binson_write_array_begin( binson_writer *pw );
void binson_write_array_end( binson_writer *pw );
void binson_write( binson_writer *pw, const uint8_t token_type );
void binson_write_boolean( binson_writer *pw, bool bval );
void binson_write_integer( binson_writer *pw, int64_t ival );
void binson_write_double( binson_writer *pw, double dval );
void binson_write_string( binson_writer *pw, const char* pstr );
void binson_write_name( binson_writer *pw, const char* pstr );
void binson_write_name_bbuf( binson_writer *pw, bbuf* pbbuf );
void binson_write_string_with_len( binson_writer *pw, const char* pstr, binson_tok_size len );
void binson_write_string_bbuf( binson_writer *pw, bbuf* pbbuf );
void binson_write_bytes( binson_writer *pw, const uint8_t* pbuf, binson_tok_size len );
void binson_write_bytes_bbuf( binson_writer *pw, bbuf* pbbuf );

/* write binson-encoded block */
uint8_t binson_write_raw( binson_writer *pw, const uint8_t *psrc, binson_size sz );

/* status getters */
static inline binson_large_size binson_writer_get_counter( binson_writer *pw ) { return pw->io.counter; }
static inline uint8_t binson_writer_geterror( binson_writer *pw, uint8_t bitmask ) { return CHECKBITMASK(pw->error_flags, bitmask); }

/*======================== PARSER ===============================*/

 /* forward declarations */

struct binson_parser;
typedef struct binson_parser binson_parser;

/* parser callback declaration */
typedef bool (*binson_parser_cb)( binson_parser *pp, uint8_t new_state, void *param );

/* main parser "object" structure */
struct binson_parser
{
  binson_io    	    io;
  uint8_t   	      state;
  uint8_t   	      error_flags;

  uint8_t	          val_type;
  bbuf  	          name;
  binson_value      val;

  uint8_t           depth;
  uint8_t           block_stack[MAX_DEPTH];  

  binson_parser_cb  cb;
  void*             cb_param;  

};

/* parser object initialization / reset */
void binson_parser_init( binson_parser *pp, uint8_t *pbuf, binson_size buf_size );
void binson_parser_reset( binson_parser *pp );
void binson_parser_set_callback( binson_parser *pp, binson_parser_cb cb, void *cb_param );

/* main parser traversal call. returns true, if advance request was satisfied according to 'scan_flag' */
bool binson_parser_advance( binson_parser *pp, uint8_t scan_flag, int16_t n_steps,
                            const char *scan_name, uint8_t ensure_type );

/* next calls are now just shortcuts to 'binson_parser_advance()' */
bool binson_parser_at_ensure( binson_parser *pp, uint8_t idx, uint8_t ensure_type );
bool binson_parser_field_ensure( binson_parser *pp, const char *scan_name, uint8_t ensure_type);
bool binson_parser_next_ensure( binson_parser *pp, uint8_t ensure_type);
bool binson_parser_go_into( binson_parser *pp );
bool binson_parser_go_into_object( binson_parser *pp );
bool binson_parser_go_into_array( binson_parser *pp );
bool binson_parser_go_up( binson_parser *pp );

/* looped "_go_up()" version, moving up till required block type */
bool binson_parser_go_upto_object( binson_parser *pp );
bool binson_parser_go_upto_array( binson_parser *pp );

/* wrappers usefull to ignore value type checks */
#define binson_parser_at(x, idx)  binson_parser_at_ensure(x, idx, BINSON_ID_UNKNOWN)
#define binson_parser_field(x, y)  binson_parser_field_ensure(x, y, BINSON_ID_UNKNOWN)
#define binson_parser_next(x)  binson_parser_next_ensure(x, BINSON_ID_UNKNOWN)

/* obsolete, do not use in v2 */
#define binson_parser_next_field(x)        binson_parser_next_ensure(x, BINSON_ID_UNKNOWN)
#define binson_parser_next_array_value(x)  binson_parser_next_ensure(x, BINSON_ID_UNKNOWN)

/* get location and size of buffer part which reflects whole current block being parsed */
bool binson_parser_get_raw( binson_parser *pp, bbuf *pbb );

/* copy current block to specified writer */
bool binson_parser_to_writer( binson_parser *pp, binson_writer *pw );

#ifdef WITH_TO_STRING
bool binson_parser_to_string( binson_parser *pp, uint8_t *pbuf, binson_size buf_size, bool nice );
#endif

static inline uint8_t   binson_parser_get_depth( binson_parser *pp ) { return pp->depth; }
static inline uint8_t 	binson_parser_get_type( binson_parser *pp ) { return pp->val_type; }
uint8_t 	binson_parser_get_boolean( binson_parser *pp );
int64_t 	binson_parser_get_integer( binson_parser *pp );
double 	    binson_parser_get_double( binson_parser *pp );
static inline uint8_t     binson_parser_geterror( binson_parser *pp, uint8_t bitmask ) { return CHECKBITMASK(pp->error_flags, bitmask ); }

static inline bbuf* 		binson_parser_get_name_bbuf( binson_parser *pp ) { return &pp->name; }
static inline binson_tok_size	binson_parser_get_name_len( binson_parser *pp ) { return pp->name.bsize; }

void binson_parser_get_name_copy( binson_parser *pp, char *dst );
int	 binson_parser_cmp_name( binson_parser *pp, const char *pstr );
bool binson_parser_name_equals( binson_parser *pp, const char *pstr );

bbuf*  binson_parser_get_string_bbuf( binson_parser *pp );
static inline void   binson_parser_cpy_string_bbuf( binson_parser *pp, bbuf *pbb ) { pbb->bptr = pp->val.bbuf_val.bptr;  pbb->bsize = pp->val.bbuf_val.bsize; }

void    binson_util_set_bbuf( bbuf *pbb, uint8_t *bptr, binson_size bsize );
void    binson_util_set_bbuf_for_asciiz( bbuf *pbb, const char* pstr );
void    binson_util_cpy_bbuf( bbuf *dst, bbuf *src );
void    binson_util_cpy_bbuf2bbuf( bbuf *dst, bbuf *src );
int     binson_util_cmp_bbuf2bbuf( bbuf *bb1, bbuf *bb2 );
int     binson_util_cmp_bbuf2asciiz( bbuf *bb1, const char* pstr );
void    binson_util_cpy_bbuf2asciiz( char* pstr, bbuf *bb );

binson_tok_size	binson_parser_get_string_len( binson_parser *pp );
void 			binson_parser_get_string_copy( binson_parser *pp, char *dst );
int	 		    binson_parser_cmp_string( binson_parser *pp, const char *pstr );
bool	 		binson_parser_string_equals( binson_parser *pp, const char *pstr );

bbuf* binson_parser_get_bytes_bbuf( binson_parser *pp );
binson_tok_size	binson_parser_get_bytes_len( binson_parser *pp );

void	 		binson_parser_get_bytes_copy( binson_parser *pp, bbuf *pbb );
int	  		binson_parser_cmp_bytes( binson_parser *pp, bbuf *pbb );
bool	 		binson_parser_bytes_equals( binson_parser *pp, bbuf *pbb );

#endif /* BINSON_LIGHT_H_INCLUDED */
