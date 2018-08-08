#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>

#include <pybind11/pybind11.h>

#include <dlisio/dlisio.h>
#include <dlisio/types.h>

namespace py = pybind11;
using namespace py::literals;

namespace {

struct io_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
    explicit io_error( int no ) : runtime_error( std::strerror( no ) ) {}
};

struct eof_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

void runtime_warning( const char* msg ) {
    int err = PyErr_WarnEx( PyExc_RuntimeWarning, msg, 1 );
    if( err ) throw py::error_already_set();
}

void getbytes( char* buffer, std::size_t nmemb, std::FILE* fd ) {
    const auto read = std::fread( buffer, 1, nmemb, fd );
    if( read != nmemb ) {
        if( std::feof( fd ) ) throw eof_error( "unexpected EOF" );
        throw io_error( errno );
    }
}

struct bookmark {
    std::fpos_t pos;

    /* 
     * the remaining bytes of the "previous" visible record. if 0, the current
     * object is the visible record label
     */
    int residual = 0;
    int isexplicit = 0;
};


class file {
public:
    file( const std::string& path );

    operator std::FILE*() const {
        if( this->fp ) return this->fp.get();
        throw py::value_error( "I/O operation on closed file" );
    }

    void close() { this->fp.reset(); }
    bool eof();

    py::dict storage_unit_label();
    py::tuple index_record( int );
    py::dict parse_elfr( const bookmark& );


private:
    struct fcloser {
        void operator()( std::FILE* x ) {
            if( x ) std::fclose( x );
        }
    };

    std::unique_ptr< std::FILE, fcloser > fp;
};

file::file( const std::string& path ) : fp( std::fopen( path.c_str(), "rb" ) ) {
    if( !this->fp ) throw io_error( errno );
}

py::dict file::storage_unit_label() {
    char buffer[ 80 ];
    getbytes( buffer, sizeof( buffer ), *this );

    char id[ 61 ] = {};
    int seqnum, major, minor, layout;
    int64_t maxlen;

    auto err = dlis_sul( buffer, &seqnum,
                                 &major,
                                 &minor,
                                 &layout,
                                 &maxlen,
                                 id );

    if( err ) throw py::value_error( "unable to parse SUL" );

    std::string version = std::to_string( major )
                        + "."
                        + std::to_string( minor );

    std::string laystr = "record";
    if( layout != DLIS_STRUCTURE_RECORD ) laystr = "unknown";

    return py::dict( "sequence"_a = seqnum,
                     "version"_a = version.c_str(),
                     "layout"_a = laystr.c_str(),
                     "maxlen"_a = maxlen,
                     "id"_a =  id );
}

int visible_length( std::FILE* fp ) {
    char buffer[ 4 ];
    getbytes( buffer, 4, fp );

    int len, version;
    const auto err = dlis_vrl( buffer, &len, &version );
    if( err ) throw py::value_error( "unable to parse visible record label" );

    if( version != 1 ) {
        std::string msg = "VRL DLIS not v1, was " + std::to_string( version );
        runtime_warning( msg.c_str() );
    }

    return len;
}

struct segheader {
    std::uint8_t attrs;
    int len;
    int type;
};

segheader segment_header( std::FILE* fp ) {
    char buffer[ 4 ];
    getbytes( buffer, 4, fp );

    segheader seg;
    const auto err = dlis_lrsh( buffer, &seg.len, &seg.attrs, &seg.type );
    if( err ) throw py::value_error( "unable to parse "
                                     "logical record segment header" );
    return seg;
}

bool file::eof() {
    std::FILE* fd = *this;

    int c = std::fgetc( fd );

    if( c == EOF ) return true;
    else c = std::ungetc( c, fd );

    if( c == EOF ) return true;
    return std::feof( fd );
}

struct markr {
    bookmark m;
    int residual;
};

markr mark( std::FILE* fp, int remaining ) {
    bookmark mark;
    mark.residual = remaining;

    auto err = std::fgetpos( fp, &mark.pos );
    if( err ) throw io_error( "unable to get stream position" );

    while( true ) {

        /* 
         * if remaining = 0 (this is at the VRL, skip the inner-loop and read
         * it
         */
        while( remaining > 0 ) {

            auto seg = segment_header( fp );
            remaining -= seg.len;

            int has_predecessor = 0;
            int has_successor = 0;
            int is_encrypted = 0;
            int has_encryption_packet = 0;
            int has_checksum = 0;
            int has_trailing_length = 0;
            int has_padding = 0;
            dlis_segment_attributes( seg.attrs, &mark.isexplicit,
                                                &has_predecessor,
                                                &has_successor,
                                                &is_encrypted,
                                                &has_encryption_packet,
                                                &has_checksum,
                                                &has_trailing_length,
                                                &has_padding );

            seg.len -= 4; // size of LRSH
            err = std::fseek( fp, seg.len, SEEK_CUR );
            if( err ) throw io_error( errno );

            if( !has_successor ) return { mark, remaining };
        }

        /* if prev.residual is 0, then we're at a VRL */
        remaining = visible_length( fp ) - 4;
    }
}

py::tuple file::index_record( int remaining ) {
    auto next = mark( *this, remaining );
    return py::make_tuple( next.m, next.residual, next.m.isexplicit );
}

std::vector< char > getrecord( std::FILE* fp, int remaining ) {

    std::vector< char > cat;
    cat.reserve( 8192 );

    while( true ) {

        while( remaining > 0 ) {

            auto seg = segment_header( fp );
            remaining -= seg.len;

            int explicit_formatting = 0;
            int has_predecessor = 0;
            int has_successor = 0;
            int is_encrypted = 0;
            int has_encryption_packet = 0;
            int has_checksum = 0;
            int has_trailing_length = 0;
            int has_padding = 0;
            dlis_segment_attributes( seg.attrs, &explicit_formatting,
                                                &has_predecessor,
                                                &has_successor,
                                                &is_encrypted,
                                                &has_encryption_packet,
                                                &has_checksum,
                                                &has_trailing_length,
                                                &has_padding );


            seg.len -= 4; // size of LRSH
            const auto prevsize = cat.size();
            cat.resize( prevsize + seg.len );
            getbytes( cat.data() + prevsize, seg.len, fp );

            if( has_trailing_length ) cat.erase( cat.end() - 2, cat.end() );
            if( has_checksum )        cat.erase( cat.end() - 2, cat.end() );
            if( has_padding ) {
                std::uint8_t padbytes = 0;
                dlis_ushort( cat.data() + cat.size() - 1, &padbytes );
                cat.erase( cat.end() - padbytes, cat.end() );
            }

            if( !has_successor ) return cat;
        }

        remaining = visible_length( fp ) - 4;
    }
}

struct set_flags {
    int type, name;
};

set_flags set_attributes( std::uint8_t attr ) {
    int role;
    auto err = dlis_component( attr, &role );
    if( err ) throw py::value_error( "unknown role " + std::to_string( attr ) );
    if( role != DLIS_ROLE_SET )
        throw py::value_error( "excepted SET, was " + std::to_string( attr ) );

    set_flags flags = {};
    err = dlis_component_set( attr, role, &flags.type, &flags.name );

    if( err ) throw py::value_error( "error parsing SET component, was "
                                     + std::to_string( attr ) );

    return flags;
}

std::string ident( const char*& xs ) {
    char str[ 256 ];
    std::int32_t len;

    dlis_ident( xs, &len, nullptr );
    xs = dlis_ident( xs, &len, str );

    return { str, str + len };
}

std::string ascii( const char*& xs ) {
    std::vector< char > str;
    std::int32_t len;

    dlis_ascii( xs, &len, nullptr );
    str.resize( len );
    xs = dlis_ascii( xs, &len, str.data() );

    return { str.begin(), str.end() };
}

float fsingl( const char*& xs ) {
    float x;
    xs = dlis_fsingl( xs, &x );
    return x;
}

int unorm( const char*& xs ) {
    std::uint16_t x;
    xs = dlis_unorm( xs, &x );
    return x;
}

long uvari( const char*& xs ) {
    std::int32_t x;
    xs = dlis_uvari( xs, &x );
    return x;
}

int ushort( const char*& xs ) {
    std::uint8_t x;
    xs = dlis_ushort( xs, &x );
    return x;
}

int status( const char*& xs ) {
    std::uint8_t x;
    xs = dlis_status( xs, &x );
    return x;
}

void dtime( const char*& xs ) {
    int Y, TZ, M, D, H, MN, S, MS;
    xs = dlis_dtime( xs, &Y, &TZ, &M, &D, &H, &MN, &S, &MS );
}

py::object array( int count, int reprc, const char*& xs ) {
    py::list l;

    for( int i = 0; i < count; ++i ) {
        switch( reprc ) {
            case DLIS_FSINGL: l.append( fsingl( xs ) ); break;
            case DLIS_UNORM:  l.append( unorm( xs ) );  break;
            case DLIS_UVARI:  l.append( uvari( xs ) );  break;
            case DLIS_IDENT:  l.append( ident( xs ) );  break;
            case DLIS_ASCII:  l.append( ascii( xs ) );  break;
            case DLIS_DTIME:  l.append( "date-time" );  dtime( xs ); break;
            case DLIS_STATUS: l.append( status( xs ) ); break;

            default:
                throw py::value_error( "unknown array type " + std::to_string( reprc ) );
        }
    }

    if( count == 1 ) return l[ 0 ];

    return l;
}

py::dict file::parse_elfr( const bookmark& pos ) {
    std::FILE* fd = *this;
    auto err = std::fsetpos( fd, &pos.pos );
    if( err ) throw io_error( errno );

    auto cat = getrecord( fd, pos.residual );
    const auto* cur = cat.data();
    const auto* end = cat.data() + cat.size();

    /* first, expect SET */
    std::uint8_t descriptor;
    std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );
    cur += sizeof( std::uint8_t );

    auto set = set_attributes( descriptor );
    py::dict record( "type"_a = py::none() );

    if( set.type ) record["type"] = ident( cur );
    if( set.name ) record["name"] = ident( cur );

    /* then, chomp through the template */

    py::list templ, invariant;
    while( true ) {
        /* assume there HAS to be a template */

        std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );

        int role;
        auto err = dlis_component( descriptor, &role );
        if( err ) throw py::value_error( "unknown role " + std::to_string( descriptor ) );

        if( role == DLIS_ROLE_OBJECT ) break;
        switch( role ) {
            case DLIS_ROLE_RESERV:
                throw py::value_error( "expected attribute, got reserved" );

            case DLIS_ROLE_RDSET:
            case DLIS_ROLE_RSET:
            case DLIS_ROLE_SET:
                throw py::value_error( "expected attribute, got SET" );

            default: break;
        }

        cur += sizeof( std::uint8_t );

        py::dict entry( "count"_a = 1,
                        "reprc"_a = DLIS_IDENT,
                        "value"_a = py::none() );

        int label;
        int count;
        int reprc;
        int units;
        int value;
        err = dlis_component_attrib( descriptor, role, &label,
                                                       &count,
                                                       &reprc,
                                                       &units,
                                                       &value );

        if( err ) throw py::value_error( "error parsing component-object" );
        if( !label ) throw py::value_error( "no label in template-attribute" );

                    entry["label"] = ident( cur );
        if( count ) entry["count"] = uvari( cur );
        if( reprc ) entry["reprc"] = ushort( cur );
        if( units ) entry["units"] = ident( cur );
        if( value ) entry["value"] = array( entry["count"].cast< int >(),
                                            entry["reprc"].cast< int >(),
                                            cur );

        if( role == DLIS_ROLE_INVATR ) invariant.append( entry );
        else                           templ.append( entry );
    }

    /* now parse objects */
    py::dict objects;
    while( true ) {
        if( cur == end ) break;

        std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );
        cur += sizeof( std::uint8_t );

        int role;
        auto err = dlis_component( descriptor, &role );
        if( err ) throw py::value_error( "unknown role "
                                       + std::to_string( descriptor ) );

        if( role != DLIS_ROLE_OBJECT )
            throw py::value_error( "expected OBJECT, was " + std::to_string( role ) );

        /* just assume obname */
        auto origin = uvari( cur );
        auto copy = ushort( cur );
        auto id = ident( cur );

        auto row = templ;
        for( auto& col : row ) {
            if( cur == end ) break;
            std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );

            int role;
            auto err = dlis_component( descriptor, &role );
            if( err ) throw py::value_error( "unknown role "
                                             + std::to_string( descriptor ) );

            if( role == DLIS_ROLE_OBJECT ) break;
            switch( role ) {
                case DLIS_ROLE_ATTRIB:
                case DLIS_ROLE_ABSATR:
                    break;

                default:
                    throw py::value_error( "role not attribute, was " + std::to_string( role ) );
            }
            cur += sizeof( std::uint8_t );

            if( role == DLIS_ROLE_ABSATR ) {
                col[ "value" ] = py::none();
                continue;
            }

            int label;
            int count;
            int reprc;
            int units;
            int value;
            err = dlis_component_attrib( descriptor, role, &label,
                                                           &count,
                                                           &reprc,
                                                           &units,
                                                           &value );

            if( label ) throw py::value_error( "label in object attribute" );

            if( count ) col["count"] = uvari( cur );
            if( reprc ) col["reprc"] = ushort( cur );
            if( units ) col["units"] = ident( cur );
            if( value ) col["value"] = array( col[ "count" ].cast< int >(),
                                              col[ "reprc" ].cast< int >(),
                                              cur );
        }

        for( auto& inv : invariant )
            row.append( inv );

        objects[py::make_tuple(origin, copy, id)] = row;
    }

    for( auto& inv : invariant )
        templ.append(inv);

    record["template"] = templ;
    record["objects"] = objects;
    return record;
}

}

PYBIND11_MODULE(core, m) {
    py::register_exception_translator( []( std::exception_ptr p ) {
        try {
            if( p ) std::rethrow_exception( p );
        } catch( const io_error& e ) {
            PyErr_SetString( PyExc_IOError, e.what() );
        } catch( const eof_error& e ) {
            PyErr_SetString( PyExc_EOFError, e.what() );
        }
    });

    py::class_< bookmark >( m, "bookmark" );

    py::class_< file >( m, "file" )
        .def( py::init< const std::string& >() )
        .def( "close", &file::close )
        .def( "eof",   &file::eof )

        .def( "sul",  &file::storage_unit_label )
        .def( "mark", &file::index_record )
        .def( "elfr", &file::parse_elfr )
        ;
}
