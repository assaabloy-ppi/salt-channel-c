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

#include "binson_light.h"

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/*====================== binson_writer private / forward decl ================*/
static void _binson_writer_write_token( binson_writer *pwriter, const uint8_t token_type, binson_value *val );

void binson_write_object_begin( binson_writer *pw );
void binson_write_object_end( binson_writer *pw );
void binson_write_array_begin( binson_writer *pw );
void binson_write_array_end( binson_writer *pw );
void binson_write_boolean( binson_writer *pw, bool bval );
void binson_write_integer( binson_writer *pw, int64_t ival );
void binson_write_double( binson_writer *pw, double dval );
void binson_write_string( binson_writer *pw, const char* pstr );
void binson_write_name( binson_writer *pw, const char* pstr );
void binson_write_string_with_len( binson_writer *pw, const char* pstr, binson_tok_size len );
void binson_write_bytes( binson_writer *pw, const uint8_t* pbuf, binson_tok_size len );

/*======================== binson_parser private / forward decl ==============*/

/* internal parser states definition */
#define BINSON_PARSER_STATE_ZERO			    0x00
#define BINSON_PARSER_STATE_BEFORE_FIELD		0x01
#define BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE  0x02
#define BINSON_PARSER_STATE_BEFORE_ARRAY		0x03
#define BINSON_PARSER_STATE_END_OF_ARRAY		0x04
#define BINSON_PARSER_STATE_BEFORE_OBJECT		0x05
#define BINSON_PARSER_STATE_END_OF_OBJECT		0x06

uint8_t _binson_parser_parse_begin( binson_parser *pp );
uint8_t _binson_parser_parse_field_name( binson_parser *pp, uint8_t type_before_name );
uint8_t _binson_parser_parse_value( binson_parser *pp, uint8_t type_byte, uint8_t after_value_state );
uint8_t _binson_parser_process_lenval( binson_parser *pp, bbuf *pbb, uint8_t len_sizeof ); /* helper to process vatriable length tokens: int+data*/

/*================== binson_io private / forward declaration =================*/

static inline void	    _binson_io_reset( binson_io *io );
static inline void      _binson_io_init( binson_io *io, uint8_t *pbuf, binson_size size );
static inline void	    _binson_io_purge( binson_io *io );
static inline uint8_t	_binson_io_write( binson_io *io, const uint8_t *psrc, binson_size sz );
static inline uint8_t	_binson_io_write_byte( binson_io *io, const uint8_t src_byte );
static inline uint8_t   _binson_io_read( binson_io *io, uint8_t *pdst, binson_size sz );
static inline uint8_t   _binson_io_read_byte( binson_io *io, uint8_t *perr );
static inline uint8_t   _binson_io_advance( binson_io *io, binson_size offset );
static inline uint8_t*	_binson_io_get_ptr( binson_io *io );

/*=================== utility private / forward declaration ==================*/

static uint8_t		_binson_util_pack_integer( int64_t val, uint8_t *pbuf, uint8_t force_64bit );
static int64_t		_binson_util_unpack_integer( uint8_t *pbuf, uint8_t bsize );
static inline uint8_t	_binson_util_sizeof_idx( uint8_t n );

/*============================================================================*/
/*============================================================================*/

/* Initialize writer object and associate it with buffer specified */
/* No real writes happen if pbuf is NULL or buf_size is zero
 * but this use case allows to calculate resulting block size by calling
 * binson_writer_get_counter() after running all required binson_write_* calls */
void binson_writer_init( binson_writer *pw, uint8_t *pbuf, binson_size buf_size )
{
  memset( pw, 0, sizeof(binson_writer) );
  _binson_io_init( &(pw->io), pbuf, buf_size );
}

/* Reset writer "object" to same state it had after last binson_writer_init_init() call */
void binson_writer_reset( binson_writer *pw )
{
  binson_writer_purge( pw );
  _binson_io_reset( &(pw->io) );

  pw->error_flags = 0;
}

/* Purge all stored bytes, preserving counters. May be helpful in streaming scenarios */
void binson_writer_purge( binson_writer *pw )
{
  _binson_io_purge( &(pw->io) );
}

/*======================== IO (smart buffer helpers) =========================*/

/* Initialize io object and associate it with buffer specified */
static inline void _binson_io_init( binson_io *io, uint8_t *pbuf, binson_size size )
{
  io->pbuf = pbuf;
  io->buf_size = size;
  _binson_io_reset( io );
}

/* Reset io "object" to same state it had after last _binson_io_init() call*/
static inline void _binson_io_reset( binson_io *io )
{
  io->buf_used	= 0;
  io->counter	= 0;
}

/* Purge all stored bytes, preserving counters. May be helpful in streaming scenarios */
static inline void _binson_io_purge( binson_io *io )
{
  io->buf_used = 0;
}

/* Write sz bytes from buffer pointed with psrc to internal buffer, with overflow checks */
static inline uint8_t	_binson_io_write( binson_io *io, const uint8_t *psrc, binson_size sz )
{
  io->counter += sz;

  if (io->buf_used + sz > io->buf_size)
    return BINSON_ID_BUF_FULL;

  if (io->pbuf)
      memcpy( io->pbuf + io->buf_used, psrc, sz );

  io->buf_used += sz;
  
  return BINSON_ID_OK;
}

/* Write single byte to internal buffer, with overflow checks */
static inline uint8_t	_binson_io_write_byte( binson_io *io, const uint8_t src_byte )
{
  return _binson_io_write( io, &src_byte, 1 );
}

/* Read sz bytes from internal buffer to memory location pointed with pdst, with bound checks, return error code if any */
static inline uint8_t _binson_io_read( binson_io *io, uint8_t *pdst, binson_size sz )
{
  if (io->buf_used + sz > io->buf_size)
      return BINSON_ID_PARSE_END_OF_BUFFER;

  io->counter += sz;

  if (io->counter > io->buf_size)
  {
    sz -= io->counter - io->buf_size;
    io->counter = io->buf_size;
  }

  if (pdst && io->pbuf)
      memcpy( pdst, io->pbuf + io->buf_used, sz );

  io->buf_used += sz;

  return BINSON_ID_OK;
}

/* Read and return single byte from internal buffer, advancing internal read position to next byte */
static inline uint8_t _binson_io_read_byte( binson_io *io, uint8_t *perr )
{
  uint8_t b;
  *perr = _binson_io_read( io, &b, 1 );
  return b;
}

/* Advance internal read position by offset bytes, return error code if any */
static inline uint8_t _binson_io_advance( binson_io *io, binson_size offset )
{
  return _binson_io_read( io, NULL, offset );
}

/* Get pointer to memory location at current read position */
static inline uint8_t*	_binson_io_get_ptr( binson_io *io )
{
  return &(io->pbuf[io->buf_used]);
}

/* Unified private method to write full binary representation for specified token_type and val */
void  _binson_writer_write_token( binson_writer *pwriter, const uint8_t token_type, binson_value *val )
{
  uint8_t 		res 	= 0;  /* write result */
  binson_tok_size 	isize 	= 1;
  UNUSED(res);

  switch (token_type)
  {
    /* optimization: top cases are most probable cases */
    case BINSON_ID_INTEGER:
    case BINSON_ID_STRING_LEN:
    case BINSON_ID_BYTES_LEN:
    case BINSON_ID_DOUBLE:
    {
      uint8_t pack_buf[ sizeof(int64_t) + 1 ];

      isize = _binson_util_pack_integer( val->int_val, &(pack_buf[1]), (token_type == BINSON_ID_DOUBLE)? 1:0 );
      pack_buf[0] = (uint8_t)(token_type + ((token_type == BINSON_ID_DOUBLE)? 0 : _binson_util_sizeof_idx( (uint8_t)isize )));
      isize++;
      res = _binson_io_write( &(pwriter->io), pack_buf, isize );

      break;
    }

    case BINSON_ID_STRING:
    case BINSON_ID_BYTES:
    {
      binson_tok_size 	tok_size = val->bbuf_val.bsize;
      binson_value 	tval;

      tval.int_val = tok_size;

      _binson_writer_write_token( pwriter, (uint8_t)(token_type+1), &tval ); /* writes type+len*/
      res = _binson_io_write( &(pwriter->io), val->bbuf_val.bptr, tok_size );  /* writes payload: string (without \0) or bytearray */
      isize += tok_size;
      break;
    }

    case BINSON_ID_OBJ_BEGIN:
    case BINSON_ID_ARRAY_BEGIN:
    case BINSON_ID_OBJ_END:
    case BINSON_ID_ARRAY_END:
    case BINSON_ID_TRUE:
    case BINSON_ID_FALSE:
      res = _binson_io_write_byte( &(pwriter->io), token_type );
      break;

    case BINSON_ID_BOOLEAN:
      res = _binson_io_write_byte( &(pwriter->io), val->bool_val? BINSON_ID_TRUE : BINSON_ID_FALSE );
      break;

    default:
    return;
  }

  if (res)
    pwriter->error_flags = res;

  return;
}

/* Write OBJECT_BEGIN token */
void binson_write_object_begin( binson_writer *pw )
{
  _binson_writer_write_token( pw, BINSON_ID_OBJ_BEGIN, NULL );
}

/* Write OBJECT_END token */
void binson_write_object_end( binson_writer *pw )
{
  _binson_writer_write_token( pw, BINSON_ID_OBJ_END, NULL );
}

/* Write ARRAY_BEGIN token */
void binson_write_array_begin( binson_writer *pw )
{
  _binson_writer_write_token( pw, BINSON_ID_ARRAY_BEGIN, NULL );
}

/* Write ARRAY_END token */
void binson_write_array_end( binson_writer *pw )
{
  _binson_writer_write_token( pw, BINSON_ID_ARRAY_END, NULL );
}

/* Write BOOLEAN token */
void binson_write_boolean( binson_writer *pw, bool bval )
{
  pw->tmp_val.bool_val = bval;
  _binson_writer_write_token( pw, BINSON_ID_BOOLEAN, &(pw->tmp_val) );
}

/* Write INTEGER token */
void binson_write_integer( binson_writer *pw, int64_t ival )
{
  pw->tmp_val.int_val = ival;
  _binson_writer_write_token( pw, BINSON_ID_INTEGER, &(pw->tmp_val) );
}

/* Write DOUBLE token */
void binson_write_double( binson_writer *pw, double dval )
{
  pw->tmp_val.double_val = dval;
  _binson_writer_write_token( pw, BINSON_ID_DOUBLE, &(pw->tmp_val) );
}

/* Write STRING token specified by zero-terminated string pointed with pstr */
void binson_write_string( binson_writer *pw, const char* pstr )
{
  binson_write_string_with_len( pw, pstr, strlen(pstr) );
}

/* Write name part of composite token specified by zero-terminated string pointed with pstr*/
void binson_write_name( binson_writer *pw, const char* pstr )
{
  pw->tmp_val.bbuf_val.bptr = (uint8_t *)pstr;
  pw->tmp_val.bbuf_val.bsize = strlen(pstr);
  _binson_writer_write_token( pw, BINSON_ID_STRING, &pw->tmp_val );
}

/* Write STRING token specified by pointer pstr and number of bytes len */
void binson_write_string_with_len( binson_writer *pw, const char* pstr, binson_tok_size len )
{
  pw->tmp_val.bbuf_val.bptr = (uint8_t *)pstr;
  pw->tmp_val.bbuf_val.bsize = len;
 _binson_writer_write_token( pw, BINSON_ID_STRING, &pw->tmp_val );
}

/* Write STRING token specified by bbuf */
void binson_write_string_bbuf( binson_writer *pw, bbuf* pbbuf )
{
  binson_util_cpy_bbuf( &pw->tmp_val.bbuf_val, pbbuf );
  _binson_writer_write_token( pw, BINSON_ID_STRING, &pw->tmp_val );
}

/* Write BYTES token specified by pointer pbuf and number of bytes len */
void binson_write_bytes( binson_writer *pw, const uint8_t* pbuf, binson_tok_size len )
{
  pw->tmp_val.bbuf_val.bptr = (uint8_t *)pbuf;
  pw->tmp_val.bbuf_val.bsize = len;
 _binson_writer_write_token( pw, BINSON_ID_BYTES, &pw->tmp_val );
}

/*=================================== PARSER =================================*/

/* Initialize parser object and associate it with buffer specified */
void binson_parser_init( binson_parser *pp, uint8_t *pbuf, binson_size buf_size )
{
  memset( pp, 0, sizeof(binson_parser) );
  _binson_io_init( &(pp->io), pbuf, buf_size );
  binson_parser_reset( pp );
}

/* Reset parser "object" to same state it had after last binson_parser_init() call */
void binson_parser_reset( binson_parser *pp )
{
  _binson_io_reset( &(pp->io) );
  pp->error_flags	= BINSON_ID_OK;
  pp->state		    = BINSON_PARSER_STATE_ZERO;
  pp->val_type		= BINSON_ID_UNKNOWN;

  binson_util_set_bbuf( &pp->name, NULL, 0 );
}

/* Parses until an expected field with the given name is found (without considering fields of inner objects). */
void binson_parser_field( binson_parser *pp, const char *name )
{
  bbuf name_bbuf;
  binson_util_set_bbuf_for_asciiz( &name_bbuf, name );

  while (binson_parser_next_field( pp ) && !pp->error_flags)
  {
    if (!binson_util_cmp_bbuf2bbuf( &pp->name, &name_bbuf ))  /* if equal */
      return;
  }

  if (!pp->error_flags)
    pp->error_flags = BINSON_ID_PARSE_NO_FIELD_NAME;
}

/* Reads next field, returns true if a field was found and false
 * if end-of-object was reached.
 * If boolean/integer/double/bytes/string was found, the value is also read
 * and is available via appropriate getter */
bool binson_parser_next_field( binson_parser *pp )
{
    if ( pp->state == BINSON_PARSER_STATE_ZERO )
      _binson_parser_parse_begin( pp );
    else if ( pp->state == BINSON_PARSER_STATE_END_OF_OBJECT )
    {
        pp->error_flags = BINSON_ID_PARSE_END_OF_OBJECT;
        return false;
    }
    else if ( pp->state == BINSON_PARSER_STATE_BEFORE_OBJECT )
    {
        pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;
        while ( binson_parser_next_field( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return false; }
        pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;
    }
    else if ( pp->state == BINSON_PARSER_STATE_BEFORE_ARRAY )
    {
        pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE;
        while ( binson_parser_next_array_value( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return false; }
        pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;
    }

    if ( pp->state != BINSON_PARSER_STATE_BEFORE_FIELD )
    {
        pp->error_flags = BINSON_ID_PARSE_WRONG_STATE;
        return false;
    }

    {
      uint8_t type_before_name = _binson_io_read_byte( &pp->io, &pp->error_flags );
      uint8_t type_before_value;

      if (pp->error_flags != BINSON_ID_OK) return false;
      if ( type_before_name == BINSON_ID_OBJ_END )
      {
	    pp->state = BINSON_PARSER_STATE_END_OF_OBJECT;
        return false;
      }

      if (_binson_parser_parse_field_name( pp, type_before_name ) != BINSON_ID_OK) return false;
      type_before_value = _binson_io_read_byte( &pp->io, &pp->error_flags );
      if (pp->error_flags != BINSON_ID_OK) return false;
      _binson_parser_parse_value( pp, type_before_value, BINSON_PARSER_STATE_BEFORE_FIELD );
      if (pp->error_flags != BINSON_ID_OK) return false;
    }

    return true;
}

/* Reads next array value, returns true if a field was found and false if end-of-object was reached.*/
bool binson_parser_next_array_value( binson_parser *pp )
{
    if ( pp->state == BINSON_PARSER_STATE_BEFORE_ARRAY )
    {
        pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE;
        while ( binson_parser_next_array_value( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return false; }
        pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE;
    }

    if ( pp->state == BINSON_PARSER_STATE_BEFORE_OBJECT )
    {
        pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;
        while ( binson_parser_next_field( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return false; }
        pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE;
    }

    if ( pp->state != BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE )
    {
        pp->error_flags = BINSON_ID_PARSE_WRONG_STATE;
        return false;
    }

    {
      uint8_t type_byte = _binson_io_read_byte( &pp->io, &pp->error_flags );
      if (pp->error_flags != BINSON_ID_OK) return false;

      if ( type_byte == BINSON_ID_ARRAY_END )
      {
	    pp->state = BINSON_PARSER_STATE_END_OF_ARRAY;
	    return false;
      }
      if (_binson_parser_parse_value( pp, type_byte, BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE ) != BINSON_ID_OK )
        return false;
    }

    return true;
}

/* Go inside expected object */
void binson_parser_go_into_object( binson_parser *pp )
{
    if ( pp->state != BINSON_PARSER_STATE_BEFORE_OBJECT )
      pp->error_flags = BINSON_ID_PARSE_WRONG_STATE;
    else
      pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;
}

/* Go inside expected array */
void binson_parser_go_into_array( binson_parser *pp )
{
    if ( pp->state != BINSON_PARSER_STATE_BEFORE_ARRAY )
      pp->error_flags = BINSON_ID_PARSE_WRONG_STATE;
    else
      pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE;
}

/* Go outside to parent object */
void binson_parser_go_upto_object( binson_parser *pp )
{
    if ( pp->state == BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE )
      while ( binson_parser_next_array_value( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return; }

    if ( pp->state == BINSON_PARSER_STATE_BEFORE_FIELD )
      while ( binson_parser_next_field( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return; }

    if ( pp->state != BINSON_PARSER_STATE_END_OF_OBJECT && pp->state != BINSON_PARSER_STATE_END_OF_ARRAY )
      pp->error_flags = BINSON_ID_PARSE_WRONG_STATE;
    else
      pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;
}

/* Go outside to first upper parent array */
void binson_parser_go_upto_array( binson_parser *pp )
{
    if ( pp->state == BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE )
      while ( binson_parser_next_array_value( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return; }

    if ( pp->state == BINSON_PARSER_STATE_BEFORE_FIELD )
      while ( binson_parser_next_field( pp ) ) { if (pp->error_flags != BINSON_ID_OK) return; }

    if ( pp->state != BINSON_PARSER_STATE_END_OF_OBJECT && pp->state != BINSON_PARSER_STATE_END_OF_ARRAY )
      pp->error_flags = BINSON_ID_PARSE_WRONG_STATE;
    else
      pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY_VALUE;
}

/* Start parsing */
uint8_t _binson_parser_parse_begin( binson_parser *pp )
{
  if ( _binson_io_read_byte( &pp->io, &(pp->error_flags) ) != BINSON_ID_OBJ_BEGIN )
    pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE;
  else
    pp->state = BINSON_PARSER_STATE_BEFORE_FIELD;

  return pp->error_flags;
}

/* Parse expected field name */
uint8_t _binson_parser_parse_field_name( binson_parser *pp, uint8_t type_before_name )
{
    switch ( type_before_name ) {
      case BINSON_ID_STRING_8:
      case BINSON_ID_STRING_16:
      case BINSON_ID_STRING_32:
        return pp->error_flags = _binson_parser_process_lenval( pp, &pp->name, (uint8_t)(1 << (type_before_name - BINSON_ID_STRING_LEN - 1)) );

      default:
        return pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE;
    }
}

/* Unified function for parsing value with expected type type_byte */
uint8_t _binson_parser_parse_value( binson_parser *pp, uint8_t type_byte, uint8_t after_value_state )
{
  switch ( type_byte ) {
    case BINSON_ID_OBJ_BEGIN:
        pp->val_type = BINSON_ID_OBJECT;
        pp->state = BINSON_PARSER_STATE_BEFORE_OBJECT;
        return BINSON_ID_OK;
    case BINSON_ID_ARRAY_BEGIN:
        pp->val_type = BINSON_ID_ARRAY;
        pp->state = BINSON_PARSER_STATE_BEFORE_ARRAY;
        return BINSON_ID_OK;
    case BINSON_ID_FALSE:
    case BINSON_ID_TRUE:
        pp->val_type = BINSON_ID_BOOLEAN;
        pp->val.bool_val = (type_byte == BINSON_ID_TRUE);
        break;
    case BINSON_ID_DOUBLE:
        pp->val_type = BINSON_ID_DOUBLE;
        pp->val.int_val = _binson_util_unpack_integer ( _binson_io_get_ptr( &pp->io ), 8 );  /* automatic uint64_t -> double translation magic via pp->val union */
        pp->error_flags = _binson_io_advance ( &pp->io, 8 );
        break;
    case BINSON_ID_INTEGER_8:
    case BINSON_ID_INTEGER_16:
    case BINSON_ID_INTEGER_32:
    case BINSON_ID_INTEGER_64:
        pp->val_type = BINSON_ID_INTEGER;
        pp->val.int_val = _binson_util_unpack_integer ( _binson_io_get_ptr( &pp->io ), (uint8_t)(1 << (type_byte - BINSON_ID_INTEGER - 1)) );
        pp->error_flags = _binson_io_advance ( &pp->io, (binson_size)(1 << (type_byte - BINSON_ID_INTEGER - 1)) );
        break;
    case BINSON_ID_STRING_8:
    case BINSON_ID_STRING_16:
    case BINSON_ID_STRING_32:
        pp->error_flags = _binson_parser_process_lenval( pp, &pp->val.bbuf_val, (uint8_t)(1 << (type_byte - BINSON_ID_STRING_LEN - 1)) );
        pp->val_type = BINSON_ID_STRING;
        break;
    case BINSON_ID_BYTES_8:
    case BINSON_ID_BYTES_16:
    case BINSON_ID_BYTES_32:
        pp->error_flags = _binson_parser_process_lenval( pp, &pp->val.bbuf_val, (uint8_t)(1 << (type_byte - BINSON_ID_BYTES_LEN - 1)) );
        pp->val_type = BINSON_ID_BYTES;
        break;
    default:
        return pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE;
  }
  pp->state = after_value_state;
  return pp->error_flags;
}

/* Parsing helper: process variable length tokens: len+data */
uint8_t _binson_parser_process_lenval( binson_parser *pp, bbuf *pbb, uint8_t len_sizeof )
{
  binson_size len;
  int64_t     len64 = _binson_util_unpack_integer ( _binson_io_get_ptr ( &pp->io ), len_sizeof );

  if (len64 < 0 || len64 > pp->io.buf_size - pp->io.buf_used - len_sizeof)  /* abnormal length */
      return pp->error_flags = BINSON_ID_PARSE_BAD_LEN;
  else
      len = (binson_size)len64;

  binson_util_set_bbuf ( pbb, _binson_io_get_ptr ( &pp->io ) + len_sizeof, len );
  return _binson_io_advance ( &pp->io, len_sizeof + len );
}

/* Copy current token name to dst saving it as normal C-string */
void binson_parser_get_name_copy( binson_parser *pp, char *dst )
{
  binson_util_cpy_bbuf2asciiz( dst, &pp->name );
}

/* Act as strcmp() for internal current name and C-string specified with pstr */
int binson_parser_cmp_name( binson_parser *pp, const char *pstr )
{
  return binson_util_cmp_bbuf2asciiz( &pp->name, pstr );
}

/* Checks whether current field name equals to string specified with pstr */
bool binson_parser_name_equals( binson_parser *pp, const char *pstr )
{
  return binson_parser_cmp_name( pp, pstr )==0? true:false;
}

/* Copy current string to dst saving it as normal C-string */
void binson_parser_get_string_copy( binson_parser *pp, char *dst )
{
  binson_util_cpy_bbuf2asciiz( dst, &pp->val.bbuf_val );
}

/* Act as strcmp() for internal current string and C-string specified with pstr */
int binson_parser_cmp_string( binson_parser *pp, const char *pstr )
{
  return binson_util_cmp_bbuf2asciiz( &pp->val.bbuf_val, pstr );
}

/* Checks whether current string equals to string specified with pstr */
bool binson_parser_string_equals( binson_parser *pp, const char *pstr )
{
  return binson_parser_cmp_string( pp, pstr )==0? true:false;
}

/* Copy current BYTES to destination described in bbuf structure pointed with pbb */
void binson_parser_get_bytes_copy( binson_parser *pp, bbuf *pbb )
{
  binson_util_cpy_bbuf2bbuf( pbb, &pp->val.bbuf_val );
}

/* Act as memcmp() to compare current BYTES to destination described in bbuf structure pointed with pbb */
int binson_parser_cmp_bytes( binson_parser *pp, bbuf *pbb )
{
  return binson_util_cmp_bbuf2bbuf( &pp->val.bbuf_val, pbb );
}

/* Checks whether current BYTES equals to destination described in bbuf structure pointed with pbb */
bool binson_parser_bytes_equals( binson_parser *pp, bbuf *pbb )
{
  return binson_parser_cmp_bytes( pp, pbb )==0? true:false;
}

/* Getter for BOOLEAN value */
uint8_t binson_parser_get_boolean( binson_parser *pp )
{
  //return pp->val.bool_val;
  return (pp->val_type == BINSON_ID_BOOLEAN)? pp->val.bool_val : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, 0);
}

/* Getter for INTEGER value */
int64_t binson_parser_get_integer( binson_parser *pp )
{
  //return pp->val.int_val;
  return (pp->val_type == BINSON_ID_INTEGER)? pp->val.int_val : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, 0);
}

/* Getter for DOUBLE value */
double binson_parser_get_double( binson_parser *pp )
{
  //return pp->val.double_val;
  return (pp->val_type == BINSON_ID_DOUBLE)? pp->val.double_val : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, 0);
}

/* Getter for STRING value */
bbuf*  binson_parser_get_string_bbuf( binson_parser *pp )
{
  //  return  &pp->val.bbuf_val;
  return (pp->val_type == BINSON_ID_STRING)? &pp->val.bbuf_val : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, NULL);
}

/* Getter for length of the STRING value */
binson_tok_size   binson_parser_get_string_len( binson_parser *pp )
{
  //  return pp->val.bbuf_val.bsize;
  return (pp->val_type == BINSON_ID_STRING)? pp->val.bbuf_val.bsize : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, 0);
}

/* Getter for BYTES value */
bbuf* binson_parser_get_bytes_bbuf( binson_parser *pp )
{
  return &pp->val.bbuf_val; // [use next line instead of this one to find current function misuses]
  //return (pp->val_type == BINSON_ID_BYTES)? &pp->val.bbuf_val : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, NULL);
}

/* Getter for length of the BYTES value */
binson_tok_size binson_parser_get_bytes_len( binson_parser *pp )
{
  //  return pp->val.bbuf_val.bsize;
  return (pp->val_type == BINSON_ID_BYTES)? pp->val.bbuf_val.bsize : (pp->error_flags = BINSON_ID_PARSE_WRONG_TYPE, 0);
}

/*======================== UTIL ===============================*/

/* Convert LE bytearray representation of its int64_t equivalent */
static int64_t	_binson_util_unpack_integer( uint8_t *pbuf, uint8_t bsize )
{
  int64_t i64 = pbuf[bsize-1] & 0x80 ? -1LL:0;  /* prefill with ones or zeroes depending of sign presence */
  int i;

  for (i=bsize-1; i>=0; i--)
  {
    i64 <<= 8;
    i64 |= pbuf[i];
  }
  return i64;
}

/* Convert int64_t argument to its LE bytearray representation and return number of bytes occupied */
static uint8_t	_binson_util_pack_integer( int64_t val, uint8_t *pbuf, uint8_t force_64bit )
{
  const int16_t bound8 = ((int16_t)1U) << 7;
  const int32_t bound16 = ((int32_t)1U) << 15;
  const int64_t bound32 = ((int64_t)1ULL) << 31;
  int i;

  uint8_t size;

  if (force_64bit)
  {
      *((uint64_t *)pbuf) = ((uint64_t )val);
      size = sizeof(uint64_t);
  }
  else
  {
      if (val >= -bound8 && val < bound8)
          size =  sizeof(uint8_t);
      else if (val >= -bound16 && val < bound16)
          size = sizeof(uint16_t);
      else if (val >= -bound32 && val < bound32)
          size = sizeof(uint32_t);
      else
          size = sizeof(uint64_t);
  }

  for (i=0; i<size; i++)
  {
      pbuf[i] = (uint8_t)(val & 0xff);
      val >>= 8;
  }

  return size;
}

/* Integer conversion helper: convert sizeof argument to index in constant list */
static inline uint8_t	_binson_util_sizeof_idx( uint8_t n )
{
 if (n < 4)
   return n;
 else if (n == 4)
   return 3;
 else
   return 4;
}

/* bbuf initialization helper */
void binson_util_set_bbuf( bbuf *pbb, uint8_t *bptr, binson_size bsize )
{
	pbb->bptr = bptr;
	pbb->bsize = bsize;
}

/* bbuf initialization helper for C-string argument */
void binson_util_set_bbuf_for_asciiz( bbuf *pbb, const char* pstr )
{
	pbb->bptr = (uint8_t*) pstr;
	pbb->bsize = pstr? strlen( pstr ) : 0;
}

/* Copy bbuf structures, but NOT referenced content */
void binson_util_cpy_bbuf( bbuf *dst, bbuf *src )
{
  dst->bptr = src->bptr;
  dst->bsize = src->bsize;
}

/* Copy memory blocks described by src to dst location, checking destination block size */
void binson_util_cpy_bbuf2bbuf( bbuf *dst, bbuf *src )
{
  memcpy( dst->bptr, src->bptr, MIN(dst->bsize, src->bsize) );
}

/* Compare two bytearrays in lexicographical sense.  return value same as  strcmp() */
int binson_util_cmp_bbuf2bbuf( bbuf *bb1, bbuf *bb2 )
{
  int r = memcmp( bb1->bptr, bb2->bptr, MIN(bb1->bsize, bb2->bsize) );
  return (r == 0)? (int)(bb1->bsize - bb2->bsize) : r;
}

/* Compare zero-terminated string with bytearrays in lexicographical sense.  return value same as  strcmp() */
int binson_util_cmp_bbuf2asciiz( bbuf *bb1, const char* pstr )
{
  bbuf bb2 = { .bptr = (uint8_t*)pstr, .bsize = (binson_tok_size)strlen(pstr) };
  return binson_util_cmp_bbuf2bbuf( bb1, &bb2 );
}

/* Copy bytearray to zero-terminated string */
void binson_util_cpy_bbuf2asciiz( char* pstr, bbuf *bb )
{
  memcpy( pstr, bb->bptr, bb->bsize );
  pstr[bb->bsize] = '\0';
}
