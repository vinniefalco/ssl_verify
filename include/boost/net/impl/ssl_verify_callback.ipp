//
// Copyright (c) 2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/ssl_verify
//

#ifndef BOOST_NET_SSL_VERIFY_CALLBACK_IPP
#define BOOST_NET_SSL_VERIFY_CALLBACK_IPP

#include <boost/utility/string_view.hpp>

namespace boost {
namespace net {

#if BOOST_NET_SSL_VERIFY_NO_HEADER_ONLY
namespace {
#endif

namespace detail {
namespace ssl_verify {



} // ssl_verify
} // detail

#if BOOST_NET_SSL_VERIFY_NO_HEADER_ONLY
} // anonymous
#endif

#if BOOST_NET_SSL_VERIFY_NO_HEADER_ONLY
static
#else
inline
#endif
bool
ssl_verify_callback::
operator()(
    bool pre_verified,
    boost::asio::ssl::verify_context& ctx) const
{
    // Don't bother looking at certificates
    // that have failed pre-verification.
    if(! pre_verified)
        return false;

    return false;
}

} // net
} // boost

#endif
