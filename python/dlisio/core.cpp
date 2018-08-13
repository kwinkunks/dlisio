#include <bitset>
#include <cerrno>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <dlisio/dlisio.h>
#include <dlisio/types.h>

#include "typeconv.cpp"

namespace py = pybind11;
using namespace py::literals;

namespace {

/*
 * for some reason, pybind does not defined IOError, so make a quick
 * regular-looking exception like that and register its translation
 */
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

/*
 * automate the read-bytes-throw-if-fails, at least for now. file error
 * reporting isn't very sophisticated, but doesn't have to be yet.
 */
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
    py::tuple markrecord( int );
    py::bytes getrecord( const bookmark& );
    py::dict eflr( const bookmark& );

private:
    struct fcloser {
        void operator()( std::FILE* x ) {
            if( x ) std::fclose( x );
        }
    };

    std::unique_ptr< std::FILE, fcloser > fp;
};

file::file( const std::string& path ) :
    fp( std::fopen( path.c_str(), "rb" ) ) {

    if( !this->fp ) throw io_error( errno );
}

bool file::eof() {
    std::FILE* fd = *this;

    int c = std::fgetc( fd );

    if( c == EOF ) return true;
    else c = std::ungetc( c, fd );

    if( c == EOF ) return true;
    return std::feof( fd );
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

struct marker {
    bookmark m;
    int residual;
};

marker mark( std::FILE* fp, int remaining ) {
    bookmark mark;
    mark.residual = remaining;

    auto err = std::fgetpos( fp, &mark.pos );
    if( err ) throw io_error( "unable to get stream position" );

    while( true ) {

        /*
         * if remaining = 0 this is at the VRL, skip the inner-loop and read it
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

        /* if remaining is 0, then we're at a VRL */
        remaining = visible_length( fp ) - 4;
    }
}

py::tuple file::markrecord( int remaining ) {
    auto next = mark( *this, remaining );
    return py::make_tuple( next.m, next.residual, next.m.isexplicit );
}

std::vector< char > catrecord( std::FILE* fp, int remaining ) {

    std::vector< char > cat;
    cat.reserve( 8192 );

    while( true ) {

        while( remaining > 0 ) {

            auto seg = segment_header( fp );

            remaining -= seg.len;

            if( remaining < 0 )
                throw py::value_error( "underflow in cat-record" );

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

py::bytes file::getrecord( const bookmark& m ) {
    std::FILE* fd = *this;
    auto err = std::fsetpos( fd, &m.pos );
    if( err ) throw io_error( errno );

    auto cat = catrecord( fd, m.residual );
    return py::bytes( cat.data(), cat.size() );
}

py::list array( int count, int reprc, const char*& xs ) {
    py::list l;

    for( int i = 0; i < count; ++i ) {
        switch( reprc ) {
            case DLIS_FSHORT: l.append( fshort( xs ) ); break;
            case DLIS_FSINGL: l.append( fsingl( xs ) ); break;
            case DLIS_FSING1: l.append( fsing1( xs ) ); break;
            case DLIS_FSING2: l.append( fsing2( xs ) ); break;
            case DLIS_ISINGL: l.append( isingl( xs ) ); break;
            case DLIS_VSINGL: l.append( vsingl( xs ) ); break;
            case DLIS_FDOUBL: l.append( fdoubl( xs ) ); break;
            case DLIS_FDOUB1: l.append( fdoub1( xs ) ); break;
            case DLIS_FDOUB2: l.append( fdoub2( xs ) ); break;
            case DLIS_CSINGL: l.append( csingl( xs ) ); break;
            case DLIS_CDOUBL: l.append( cdoubl( xs ) ); break;
            case DLIS_SSHORT: l.append( sshort( xs ) ); break;
            case DLIS_SNORM:  l.append(  snorm( xs ) ); break;
            case DLIS_SLONG:  l.append(  slong( xs ) ); break;
            case DLIS_USHORT: l.append( ushort( xs ) ); break;
            case DLIS_UNORM:  l.append(  unorm( xs ) ); break;
            case DLIS_ULONG:  l.append(  ulong( xs ) ); break;
            case DLIS_UVARI:  l.append(  uvari( xs ) ); break;
            case DLIS_IDENT:  l.append(  ident( xs ) ); break;
            case DLIS_ASCII:  l.append(  ascii( xs ) ); break;
            case DLIS_DTIME:  l.append(  dtime( xs ) ); break;
            case DLIS_STATUS: l.append( status( xs ) ); break;
            case DLIS_OBNAME: l.append( obname( xs ) ); break;

            default:
                throw py::value_error( "unknown representation code "
                                     + std::to_string( reprc ) );
        }
    }

    return l;
}

struct set_flags {
    int type, name;
};

set_flags set_attributes( std::uint8_t attr ) {
    int role;
    auto err = dlis_component( attr, &role );
    if( err ) {
        throw py::value_error( "unable to parse eflr component "
                             + std::bitset< 8 >( attr ).to_string()
        );
    }

    switch( role ) {
        case DLIS_ROLE_RDSET:
        case DLIS_ROLE_RSET:
        case DLIS_ROLE_SET:
            break;

        default:
            throw py::value_error( std::string( "expected set, was " )
                                 + dlis_component_str( role )
                                 + " "
                                 + std::bitset< 8 >( role ).to_string()
            );
    }

    set_flags flags = {};
    err = dlis_component_set( attr, role, &flags.type, &flags.name );

    if( err )
        throw py::value_error( "unable to parse fields in eflr component" );

    return flags;
}

struct tmpl {
    std::vector< py::dict > attribute;
    std::vector< py::dict > invariant;
};

tmpl eflr_template( const char*& cur ) {
    tmpl cols;
    while( true ) {
        std::uint8_t attr;
        std::memcpy( &attr, cur, sizeof( std::uint8_t ) );

        int role;
        auto err = dlis_component( attr, &role );
        if( err )
            throw py::value_error( "template: unable to parse eflr component "
                                 + std::bitset< 8 >( attr ).to_string()
        );

        switch( role ) {
            case DLIS_ROLE_OBJECT:
                return cols;

            case DLIS_ROLE_ATTRIB:
            case DLIS_ROLE_INVATR:
                break;

            default:
                throw py::value_error(
                    std::string( "expected attribute in template, got " )
                               + dlis_component_str( role )
                );
        }

        cur += sizeof( std::uint8_t );

        /* set the global defaults unconditionally */
        py::dict col( "count"_a = 1,
                      "reprc"_a = DLIS_IDENT,
                      "value"_a = py::none() );

        int label;
        int count;
        int reprc;
        int units;
        int value;
        err = dlis_component_attrib( attr, role, &label,
                                                 &count,
                                                 &reprc,
                                                 &units,
                                                 &value );

        if( err )
            throw py::value_error( "unable to parse template attribute" );

        if( !label )
            throw py::value_error( "missing template attribute label" );

                    col["label"] = ident( cur );
        if( count ) col["count"] = uvari( cur );
        if( reprc ) col["reprc"] = ushort( cur );
        if( units ) col["units"] = ident( cur );
        if( value ) col["value"] = array( col["count"].cast< int >(),
                                          col["reprc"].cast< int >(),
                                          cur );

        if( role == DLIS_ROLE_ATTRIB ) cols.attribute.push_back( col );
        else                           cols.invariant.push_back( col );
    }
}

py::dict eflr( const std::vector< char >& cat ) {
    const auto* cur = cat.data();
    const auto* end = cat.data() + cat.size();

    std::uint8_t descriptor;
    std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );
    cur += sizeof( std::uint8_t );

    auto set = set_attributes( descriptor );
    py::dict record( "type"_a = py::none() );

    if( set.type ) record["type"] = ident( cur );
    if( set.name ) record["name"] = ident( cur );

    auto tmpl = eflr_template( cur );

    py::dict objects;
    while( true ) {
        if( cur == end ) break;

        std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );
        cur += sizeof( std::uint8_t );

        int role;
        auto err = dlis_component( descriptor, &role );
        if( err )
            throw py::value_error( "unable to parse eflr component "
                                 + std::bitset< 8 >( descriptor ).to_string()
        );

        if( role != DLIS_ROLE_OBJECT )
            throw py::value_error( std::string( "expected object, was " )
                                 + dlis_component_str( role ) );

        /* just assume obname */
        auto name = obname( cur );

        /* each object forms a row of all attributes */
        auto row = tmpl.attribute;
        for( auto& col : row ) {
            if( cur == end ) break;
            std::memcpy( &descriptor, cur, sizeof( std::uint8_t ) );

            int role;
            auto err = dlis_component( descriptor, &role );
            if( err ) throw py::value_error( "unknown role "
                                           + std::to_string( descriptor ) );

            /*
             * if a new object is encountered, default the remaining columns,
             * and move on the the next row
             */
            if( role == DLIS_ROLE_OBJECT ) break;

            switch( role ) {
                case DLIS_ROLE_ATTRIB:
                case DLIS_ROLE_ABSATR:
                    break;

                default:
                    throw py::value_error(
                        std::string( "expected attribute, found " ) +
                        dlis_component_str( role )
                    );
            }

            /*
             * only advance pointer after we know this isn't object, so that
             * the next object can assume it's at the object boundary
             */
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

            if( label ) {
                runtime_warning( "found unexpected label in object attribute, "
                                 "possibly corrupted file. label" );
                ident( cur );
            }

            if( count ) col["count"] = uvari( cur );
            if( reprc ) col["reprc"] = ushort( cur );
            if( units ) col["units"] = ident( cur );
            if( value ) col["value"] = array( col[ "count" ].cast< int >(),
                                              col[ "reprc" ].cast< int >(),
                                              cur );
        }

        /* patch invariant-attributes onto the record */
        row.insert( row.end(), tmpl.invariant.begin(), tmpl.invariant.end() );
        objects[py::make_tuple(name)] = row;
    }

    record["template-attribute"] = tmpl.attribute;
    record["template-invariant"] = tmpl.invariant;
    record["objects"] = objects;
    return record;
}

py::dict file::eflr( const bookmark& mark ) {
    std::FILE* fd = *this;
    auto err = std::fsetpos( fd, &mark.pos );
    if( err ) throw io_error( errno );

    auto cat = catrecord( fd, mark.residual );
    return ::eflr( cat );
}

}

PYBIND11_MODULE(core, m) {
    PyDateTime_IMPORT;

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

        .def( "sul",       &file::storage_unit_label )
        .def( "mark",      &file::markrecord )
        .def( "getrecord", &file::getrecord )
        .def( "eflr",      &file::eflr )
        ;
}
