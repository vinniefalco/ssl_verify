//
// Copyright (c) 2016-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/ssl_verify
//

#ifndef BOOST_NET_SSL_VERIFY_CALLBACK_HPP
#define BOOST_NET_SSL_VERIFY_CALLBACK_HPP

#include <boost/asio/ssl/verify_context.hpp>
#include <string>
#include <utility>

namespace boost {
namespace net {

/** Verify a certificate against a hostname according to the rules described in RFC 2818.

    This function object may be used with the
    `boost::asio::ssl::stream::set_verify_callback` member function.

    The algorithm consults any available platform-specific and
    operating-system certificate stores as well as revocation
    lists.
*/
class ssl_verify_callback
{
    std::string host_;

public:
    ssl_verify_callback(ssl_verify_callback const&) = default;

    explicit
    ssl_verify_callback(std::string host)
        : host_(std::move(host))
    {
    }

    bool
    operator()(
        bool pre_verified,
        boost::asio::ssl::verify_context& ctx) const;
};

} // net
} // boost

#if ! BOOST_NET_SSL_VERIFY_NO_HEADER_ONLY
#include <boost/net/impl/ssl_verify_callback.ipp>
#endif

#endif
